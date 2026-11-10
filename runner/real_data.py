"""Real public data for a project, fetched by the runner and never by a builder: public hosts on a short list, no
account or key, size caps, the license quoted from a captured page and a checksum per file. The files sit next to the
workspace, readable but not writable by the job, linked in as real_data/ and kept out of git and every model packet."""

import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import tarfile
import urllib.request
from urllib.parse import urlsplit
import zipfile

# Public hosting that serves files without an account. Anything else waits for Yash.
HOSTS = ("github.com", "githubusercontent.com", "huggingface.co", "hf.co", "zenodo.org")
# Licenses that allow reading and analysing the data in a public project that never redistributes it. Any other
# (non-commercial, restrictive, unknown) waits for Yash.
LICENSES = ("public-domain", "permissive", "attribution", "share-alike", "non-commercial", "restrictive", "unknown")
USABLE = {"public-domain", "permissive", "attribution", "share-alike"}
# Terms that rule the use out whatever class the model gave.
LIMITING = re.compile(
    r"\bnc\b|non ?commercial|\bnd\b|no ?deriv|research (use )?only|all rights reserved|proprietary"
    r"|not for (commercial|redistribution)",
    re.IGNORECASE,
)
# A first filter for hidden tests that would run a downloaded file; the final reviewer, who sees every hidden test
# of a project with real data, is the check.
RUNS = re.compile(
    r"\b(exec|eval|compile|__import__|import_module|SourceFileLoader|spec_from_file_location|runpy|"
    r"doctest|pickle|marshal|load_source|runsource|runcode|InteractiveInterpreter|ctypes)\b"
)
# Only data is kept: nothing downloaded can be imported or run.
DATA_TYPES = (
    ".csv",
    ".tsv",
    ".json",
    ".jsonl",
    ".txt",
    ".md",
    ".xml",
    ".html",
    ".yaml",
    ".yml",
    ".wav",
    ".flac",
    ".mp3",
    ".ogg",
    ".png",
    ".jpg",
    ".jpeg",
)
MAX_SOURCES = 6
MAX_FILE = 50 * 2**20
MAX_TOTAL = 200 * 2**20
MAX_MEMBERS = 2_000
PREVIEW = 1_500
NAME = re.compile(r"[a-z0-9][a-z0-9_-]{0,40}")
FOLDER = "real_data"
TEXT = (".csv", ".tsv", ".json", ".jsonl", ".txt", ".md", ".py", ".yaml", ".yml", ".xml", ".html")


def approved(url):
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    return (
        parts.scheme == "https"
        and not parts.username
        and not parts.password
        and parts.port in (None, 443)
        and any(host == h or host.endswith("." + h) for h in HOSTS)
    )


def problems(value, pages):
    """What is wrong with a model's choice of sources: each from a captured page, on a listed host, with a license
    quoted character for character from that page."""
    by_id = {p["id"]: p for p in pages}
    found = []
    if len(value["sources"]) > MAX_SOURCES:
        found.append(f"at most {MAX_SOURCES} sources")
    names = [s["name"] for s in value["sources"]]
    if len(set(names)) < len(names):
        found.append("source names must be distinct")
    for source in value["sources"]:
        page = by_id.get(source["page"])
        if not NAME.fullmatch(source["name"]):
            found.append(f"{source['name']}: names are short lowercase words with - or _")
        if not approved(source["url"]):
            found.append(f"{source['url']}: not on the public hosts {HOSTS}; list it in needs_approval instead")
        if page is None:
            found.append(f"{source['name']}: page must be the id of a captured page")
        elif source["url"] != page["url"] and source["url"] not in page["links"]:
            found.append(f"{source['name']}: the url must be the page itself or a link on it")
        elif len(source["license_quote"]) < 8 or source["license_quote"] not in page["text"]:
            found.append(f"{source['name']}: license_quote must be copied exactly from the page's text")
        if not usable(source):
            found.append(
                f"{source['name']}: a {source['license']} license, or terms that limit the use, wait for "
                "Yash; list it in needs_approval"
            )
    return found


def usable(source):
    terms = re.sub(r"[\s_-]+", " ", source.get("license_quote", ""))
    return source.get("license") in USABLE and not LIMITING.search(terms)


def runs_data(text):
    """Test code that names real_data/ and could run what it reads."""
    return FOLDER in text and bool(RUNS.search(text))


class OnListedHosts(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not approved(newurl):
            raise ValueError(f"redirect to a host that is not listed: {urlsplit(newurl).hostname}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download(url, path, room):
    """Stream one file to path, refusing more than room bytes or MAX_FILE; returns its size."""
    if not approved(url):
        raise ValueError(f"not a listed public host: {url}")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), OnListedHosts)
    request = urllib.request.Request(url, headers={"User-Agent": "arcturus-data"})
    size, limit = 0, min(MAX_FILE, room)
    with opener.open(request, timeout=120) as response, open(path, "wb") as out:
        while chunk := response.read(1 << 16):
            size += len(chunk)
            if size > limit:
                raise ValueError(f"{url} is over the {limit // 2**20} MB cap")
            out.write(chunk)
    return size


def unpack(archive, folder):
    """Unpack a zip or tar archive inside folder only, within the member and size caps; other files stay as they are."""
    if zipfile.is_zipfile(archive):
        with zipfile.ZipFile(archive) as zipped:
            members = [m for m in zipped.infolist() if not m.is_dir()]
            check_members([(m.filename, m.file_size) for m in members])
            zipped.extractall(folder)
    elif tarfile.is_tarfile(archive):
        with tarfile.open(archive) as tarred:
            if any(not (m.isfile() or m.isdir()) for m in tarred.getmembers()):
                raise ValueError("archive holds links or special files; only plain files are taken")
            members = [m for m in tarred.getmembers() if m.isfile()]
            check_members([(m.name, m.size) for m in members])
            tarred.extractall(folder, filter="data")  # refuses links out, absolute paths and devices
    else:
        return False
    archive.unlink()
    return True


def check_members(members):
    if len(members) > MAX_MEMBERS or sum(size for _, size in members) > MAX_TOTAL:
        raise ValueError("archive is over the member or size cap")
    for name, _ in members:
        path = PurePosixPath(name)
        if path.is_absolute() or ".." in path.parts:
            raise ValueError(f"archive member outside its folder: {name}")


def keep_data(folder):
    """Remove every file that is not plain data, so no downloaded code can be imported or run; True if data is left."""
    for path in [p for p in folder.rglob("*") if p.is_file()]:
        if path.suffix.lower() not in DATA_TYPES:
            path.unlink()
    return any(p.is_file() for p in folder.rglob("*"))


def digest(path):
    hashed = hashlib.sha256()
    with open(path, "rb") as file:
        while chunk := file.read(1 << 20):
            hashed.update(chunk)
    return hashed.hexdigest()


def preview(files):
    first = next((f for f in files if f.suffix.lower() in TEXT), None)
    return first.read_bytes()[:PREVIEW].decode(errors="replace") if first else ""


def retrieve(sources, base):
    """Download the chosen sources into base/real_data, readable by the job and nobody's to write. Returns what the
    spec lists for each, and why any source was left out (its folder is removed)."""
    folder, used, fetched, failed = Path(base) / FOLDER, 0, [], []
    shutil.rmtree(folder, ignore_errors=True)
    for source in sources:
        target = folder / source["name"]
        try:
            target.mkdir(parents=True)
            raw = target / (PurePosixPath(urlsplit(source["url"]).path).name or "download")
            used += download(source["url"], raw, MAX_TOTAL - used)
            unpack(raw, target)
        except (OSError, ValueError, zipfile.BadZipFile, tarfile.TarError) as exc:
            shutil.rmtree(target, ignore_errors=True)
            failed.append(f"{source['name']}: {exc}")
            continue
        fetched.append(
            {
                "path": f"{FOLDER}/{source['name']}",
                "url": source["url"],
                "page_url": source["page_url"],
                "license": source["license"],
                "license_quote": source["license_quote"],
                "why": source["why"],
            }
        )
    listing, refused = recheck(fetched, base)
    return listing, failed + refused


def recheck(listing, base):
    """Apply the license and data-only rules to each source on disk, also to one saved by an earlier run; a source
    that fails is removed. Returns the listing with fresh checksums, and why any source was left out."""
    folder, kept, refused = Path(base) / FOLDER, [], []
    for item in listing:
        target = folder / item["path"].split("/", 1)[1]
        if not usable(item) or not target.is_dir() or not keep_data(target):
            shutil.rmtree(target, ignore_errors=True)
            refused.append(f"{item['path']}: license needs Yash, or no data files (csv, json, text, audio, images)")
            continue
        files = sorted(p for p in target.rglob("*") if p.is_file())
        kept.append(
            {
                **item,
                "files": {str(f.relative_to(folder)): {"bytes": f.stat().st_size, "sha256": digest(f)} for f in files},
                "preview": preview(files),
            }
        )
    if folder.exists():
        readable(folder)
    return kept, refused


def summary(listing):
    """What a spec writer sees: each source with its first files, never the whole checksum list."""
    return [
        {**item, "files": dict(list(item["files"].items())[:50]), "file_count": len(item["files"])} for item in listing
    ]


def readable(folder):
    for path in [folder, *folder.rglob("*")]:
        os.chmod(path, 0o755 if path.is_dir() else 0o644)


def place(base, arm):
    """Replace the workspace's real_data/ with exactly the approved files (the sandbox lets tests read only the
    workspace; none when nothing was approved) and keep it out of git, so no commit or packet holds them."""
    target = Path(base) / "repo" / FOLDER
    shutil.rmtree(target, ignore_errors=True)
    if (Path(base) / FOLDER).is_dir():
        shutil.copytree(Path(base) / FOLDER, target, symlinks=True)
        readable(target)
    exclude = Path(arm) / "git" / "info" / "exclude"
    if f"/{FOLDER}" not in (exclude.read_text().split() if exclude.exists() else []):
        with open(exclude, "a") as file:
            file.write(f"/{FOLDER}\n")


def changed(workspace, listing):
    """Files whose bytes no longer match the checksum taken at download, and any file nobody approved."""
    folder = Path(workspace) / FOLDER
    expected = {name: meta["sha256"] for item in listing for name, meta in item["files"].items()}
    present = {str(p.relative_to(folder)) for p in folder.rglob("*") if p.is_file()} if folder.is_dir() else set()
    return sorted(
        n
        for n in expected.keys() | present
        if n not in present or n not in expected or digest(folder / n) != expected[n]
    )
