-- SQL Schema for the Python YOURLS Adapter
-- Based on the standard YOURLS structure

-- Dropping the table if it exists can be useful during development
-- Uncomment the next line if you want this behavior
-- DROP TABLE IF EXISTS `yourls_url`;

CREATE TABLE `yourls_url` (
  `keyword` varchar(200) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  `url` text CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL,
  `title` text CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT NULL,
  `timestamp` timestamp NOT NULL DEFAULT current_timestamp(),
  `ip` varchar(41) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL,
  `clicks` int(10) unsigned NOT NULL DEFAULT 0,
  PRIMARY KEY (`keyword`),
  KEY `timestamp` (`timestamp`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Note:
-- - Using utf8mb4 for full Unicode support.
-- - `keyword` uses a binary collation (utf8mb4_bin) for case-sensitivity, which is typical for short URLs.
-- - `url` and `title` use a general, case-insensitive collation.
-- - Added an index on `timestamp` for faster sorting by date. 