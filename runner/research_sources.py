"""Credential-free, allowlisted public HTTPS capture for research workers."""

import hashlib
import html
import http.client
import ipaddress
import json
import re
from html.parser import HTMLParser
from pathlib import Path
import socket
import ssl
from xml.etree import ElementTree
from urllib.parse import urljoin, urlsplit, urlunsplit, urlencode, parse_qs
from datetime import datetime, timezone

from api_review import encode
from workers import WorkerFailure

MAX_BODY = 2_000_000
MAX_TEXT = 100_000
FETCH_TIMEOUT = 15
SEARCH_PATHS = {"www.bing.com": "/search", "html.duckduckgo.com": "/html/", "www.google.com": "/search"}


def utcnow():
    return datetime.now(timezone.utc).isoformat()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def allowed_url(url, origins):
    if not isinstance(url, str) or len(url) > 2048 or any(ord(c) < 33 for c in url):
        raise ValueError("invalid public source URL")
    parts = urlsplit(url)
    host = parts.hostname
    path = parts.path or "/"
    if (
        any(part in {".", ".."} for part in path.split("/"))
        or "\\" in path
        or re.search(r"%(?:2e|2f|5c|00|25)", path, re.IGNORECASE)
    ):
        raise ValueError("ambiguous or traversal source path")
    if (
        parts.scheme != "https"
        or not host
        or parts.username
        or parts.password
        or parts.port not in (None, 443)
        or parts.fragment
        or host not in origins
        or host != host.encode("idna").decode()
        or not any(
            path.startswith(prefix) if prefix.endswith("/") else path == prefix or path.startswith(prefix + "/")
            for prefix in origins[host]
        )
    ):
        raise ValueError("source URL is outside the signed public origins")
    return urlunsplit(("https", host, path, parts.query, ""))


def flatten(value, key=""):
    """Readable 'parent.key: value' lines from page data that client-rendered sites embed as JSON."""
    if isinstance(value, dict):
        return [line for k, v in value.items() for line in flatten(v, f"{key.rsplit('.', 1)[-1]}.{k}".lstrip("."))]
    if isinstance(value, list):
        return [line for v in value for line in flatten(v, key)]
    if isinstance(value, str) and value.strip() and not value.startswith(("http://", "https://", "/")):
        return [f"{key}: {' '.join(html.unescape(re.sub(r'<[^>]+>', ' ', value)).split())}"]
    return []


class Page(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.hidden = 0
        self.text = []
        self.links = []
        self.published = None
        self.publication_provenance = None
        self.embedded = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag in {"script", "style", "noscript", "svg"}:
            self.hidden += 1
        if attrs.get("data-page"):
            self.embed(attrs["data-page"])
        if tag == "script" and attrs.get("id") == "__NEXT_DATA__":
            self.embedded = []
        if tag == "a" and attrs.get("href"):
            self.links.append(attrs["href"])
        if tag == "meta" and attrs.get("property", attrs.get("name")) in {
            "article:published_time",
            "datePublished",
            "date",
            "pubdate",
        }:
            self.published = attrs.get("content")
            self.publication_provenance = "meta." + attrs.get("property", attrs.get("name"))
        if (
            tag == "time"
            and attrs.get("datetime")
            and self.published is None
            and (attrs.get("itemprop") == "datePublished" or "pubdate" in attrs)
        ):
            self.published = attrs["datetime"]
            self.publication_provenance = "time.datePublished"

    def embed(self, raw):
        try:
            self.text.extend(flatten(json.loads(raw)))
        except ValueError:
            pass

    def handle_endtag(self, tag):
        if tag == "script" and self.embedded is not None:
            self.embed("".join(self.embedded))
            self.embedded = None
        if tag in {"script", "style", "noscript", "svg"} and self.hidden:
            self.hidden -= 1

    def handle_data(self, text):
        if self.embedded is not None:
            self.embedded.append(text)
        if not self.hidden and text.strip():
            self.text.append(text.strip())


class PublicHTTPS(http.client.HTTPSConnection):
    """Pin validated public DNS addresses while preserving hostname TLS verification."""

    def connect(self):
        addresses = socket.getaddrinfo(self.host, 443, type=socket.SOCK_STREAM)
        if not addresses or any(not ipaddress.ip_address(item[4][0]).is_global for item in addresses):
            raise OSError("source DNS includes a non-public address")
        address = addresses[0][4][0]
        sock = socket.create_connection((address, 443), self.timeout)
        try:
            self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
        except BaseException:
            sock.close()
            raise


class Retriever:
    def __init__(self, root, origins, limit, *, connection=PublicHTTPS, active=lambda: True):
        self.root = Path(root)
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.origins, self.limit, self.connection, self.active = origins, limit, connection, active
        self.index = self.root / "index.json"
        self.state = json.loads(self.index.read_text()) if self.index.exists() else {"attempts": 0, "captures": []}

    def save(self):
        temporary = self.root / "index.tmp"
        temporary.write_bytes(encode(self.state))
        temporary.replace(self.index)

    def read(self, item):
        raw = (self.root / (item["id"] + ".body")).read_bytes()
        if digest(raw) != item["raw_sha256"]:
            raise WorkerFailure("captured research source bytes changed")
        text = (self.root / (item["id"] + ".txt")).read_bytes().decode()
        if digest(text.encode()) != item["text_sha256"]:
            raise WorkerFailure("captured research source text changed")
        return {**item, "text": text}

    def fetch(self, url, category, *, fresh=False):
        url = allowed_url(url, self.origins)
        if not fresh:
            cached = next(
                (
                    item
                    for item in reversed(self.state["captures"])
                    if item["requested_url"] == url and item["category"] == category
                ),
                None,
            )
            if cached:
                return self.read(cached)
        requested = url
        redirects = []
        status, raw, text, published, modified, content_type = None, b"", "", None, None, None
        gap, links = None, []
        publication_provenance = None
        try:
            for hop in range(4):
                if not self.active():
                    raise WorkerFailure("research retrieval cancelled or authorization inactive")
                if self.state["attempts"] >= self.limit:
                    raise WorkerFailure("research retrieval request limit reached")
                self.state["attempts"] += 1
                self.save()
                parts = urlsplit(url)
                client = self.connection(
                    parts.hostname, port=443, timeout=FETCH_TIMEOUT, context=ssl.create_default_context()
                )
                try:
                    client.request(
                        "GET",
                        parts.path + ("?" + parts.query if parts.query else ""),
                        headers={
                            "user-agent": "ArcturusResearch/1.0",
                            "accept-encoding": "identity",
                            "accept": "text/html,text/plain,application/json",
                            "connection": "close",
                        },
                    )
                    response = client.getresponse()
                    status = response.status
                    if status in (301, 302, 303, 307, 308):
                        location = response.getheader("location")
                        if hop == 3 or not location:
                            raise ValueError("source redirect limit reached")
                        url = allowed_url(urljoin(url, location), self.origins)
                        redirects.append(url)
                        continue
                    if status != 200:
                        gap = f"public source returned HTTP {status}"
                        break
                    content_type = (response.getheader("content-type") or "").split(";")[0].lower()
                    if response.getheader("content-encoding") not in (None, "", "identity"):
                        raise ValueError("compressed source response is unsupported")
                    if content_type not in {
                        "text/html",
                        "text/plain",
                        "application/json",
                        "text/markdown",
                        "application/rss+xml",
                        "text/xml",
                        "application/xml",
                    }:
                        raise ValueError("source format requires an unsupported extractor")
                    raw = response.read(MAX_BODY + 1)
                    if len(raw) > MAX_BODY:
                        raw = raw[:MAX_BODY]
                        gap = "source body exceeded capture limit; incomplete bytes retained"
                    text = raw.decode("utf-8", errors="strict")
                    modified = response.getheader("last-modified")
                    if content_type == "text/html":
                        page = Page()
                        page.feed(text)
                        published, publication_provenance = page.published, page.publication_provenance
                        if published is None:
                            match = re.search(r'"datePublished"\s*:\s*("(?:[^"\\]|\\.){1,100}")', text)
                            if match:
                                published = json.loads(match[1])
                                publication_provenance = "embedded.datePublished"
                        text = "\n".join(page.text)
                        for link in page.links:
                            try:
                                target = urljoin(url, link).split("#")[0]
                                parts = urlsplit(target)
                                if parts.hostname == "www.google.com" and parts.path == "/url":
                                    query = parse_qs(parts.query)
                                    target = query.get("q", query.get("url", [""]))[0]
                                if parts.hostname in {"duckduckgo.com", "html.duckduckgo.com"} and parts.path == "/l/":
                                    target = parse_qs(parts.query).get("uddg", [""])[0]
                                links.append(allowed_url(target, self.origins))
                            except ValueError:
                                continue
                    elif content_type in {"application/rss+xml", "text/xml", "application/xml"}:
                        if "<!DOCTYPE" in text.upper():
                            raise ValueError("DTD source content is not permitted")
                        feed = ElementTree.fromstring(text)
                        snippets = []
                        for entry in feed.findall(".//item"):
                            target = entry.findtext("link") or ""
                            try:
                                links.append(allowed_url(target, self.origins))
                            except ValueError:
                                continue
                            snippets.append(
                                (entry.findtext("title") or "")
                                + "\n"
                                + (entry.findtext("description") or "")
                                + "\n"
                                + target
                            )
                        for location in feed.iter():
                            if location.tag.rsplit("}", 1)[-1] == "loc" and location.text:
                                try:
                                    target = allowed_url(location.text.strip(), self.origins)
                                except ValueError:
                                    continue
                                links.append(target)
                                snippets.append(target)
                        text = "\n\n".join(snippets)
                    if len(text) > MAX_TEXT:
                        text = text[:MAX_TEXT]
                        gap = "extracted text exceeded limit; source coverage is incomplete"
                    if not text.strip():
                        gap = "public source yielded no usable text; rendering or authentication may be required"
                    break
                finally:
                    client.close()
        except WorkerFailure:
            raise
        except (OSError, ValueError, ElementTree.ParseError, http.client.HTTPException):
            gap = "public retrieval failed or source format/redirect was denied"
        stamp = utcnow()
        identity = digest(encode([requested, url, stamp, digest(raw), category]))
        item = {
            "id": identity,
            "requested_url": requested,
            "url": url,
            "category": category,
            "kind": (
                "search-results"
                if urlsplit(requested).hostname in SEARCH_PATHS
                else "navigation"
                if "sitemap" in urlsplit(url).path.lower()
                else "document"
            ),
            "retrieved_at": stamp,
            "published_at": published,
            "last_modified": modified,
            "publication_provenance": publication_provenance,
            "http_status": status,
            "content_type": content_type,
            "raw_sha256": digest(raw),
            "text_sha256": digest(text.encode()),
            "gap": gap,
            "redirects": redirects,
            "links": sorted(set(links))[:100],
        }
        (self.root / (identity + ".body")).write_bytes(raw)
        (self.root / (identity + ".txt")).write_text(text)
        self.state["captures"].append(item)
        self.save()
        return {**item, "text": text}

    def search(self, query, category):
        if not isinstance(query, str) or not 1 <= len(query) <= 300:
            raise ValueError("invalid bounded public search query")
        # Public HTML search has no provider API key. Results remain unverified until fetched.
        host = next(host for host in SEARCH_PATHS if host in self.origins)
        parameters = {"q": query}
        if host == "www.bing.com":
            parameters["format"] = "rss"
        url = "https://" + host + SEARCH_PATHS[host] + "?" + urlencode(parameters)
        item = self.fetch(url, category)
        links = []
        for link in item["links"]:
            if urlsplit(link).hostname not in SEARCH_PATHS:
                links.append(link)
        if not links:
            item = {
                **item,
                "gap": item["gap"] or "no usable public search results; rendering or access may be restricted",
            }
            for captured in self.state["captures"]:
                if captured["id"] == item["id"]:
                    captured["gap"] = item["gap"]
            self.save()
        return item, links[:8]


def packet_sources(items, *, characters=3000):
    result = {}
    for item in items:
        if item["id"] in result:
            continue
        result[item["id"]] = {
            key: item.get(key)
            for key in (
                "url",
                "category",
                "kind",
                "retrieved_at",
                "published_at",
                "publication_provenance",
                "last_modified",
                "http_status",
                "raw_sha256",
                "text_sha256",
                "gap",
            )
        }
        result[item["id"]].update(
            text=item["text"][:characters],
            excerpted=len(item["text"]) > characters,
            links=item["links"][:12],
            links_omitted=max(0, len(item["links"]) - 12),
        )
    return result


def source_text(sources, identity):
    source = sources[identity]
    reference = source.get("text_ref")
    if reference is None:
        return source["text"]
    target = sources.get(reference)
    if (
        not target
        or target.get("text_ref") is not None
        or source["text"]
        or digest(target["text"].encode()) != source.get("view_sha256")
    ):
        raise WorkerFailure("invalid content-addressed research source reference")
    return target["text"]


def compact_sources(sources):
    """Keep all evidence identities and metadata, storing identical visible text once."""
    result, canonical = {}, {}
    for identity in sorted(sources):
        source = {k: v for k, v in sources[identity].items() if k != "text_ref"}
        text = source_text(sources, identity)
        hashed = digest(text.encode())
        source["view_sha256"] = hashed
        if text and hashed in canonical:
            source.update(text="", text_ref=canonical[hashed])
        else:
            source["text"] = text
            canonical[hashed] = identity
        result[identity] = source
    return result
