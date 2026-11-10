ALTER TABLE postings ADD COLUMN publication_high_water TEXT NOT NULL DEFAULT '';
PRAGMA user_version = 5;
