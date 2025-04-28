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

-- Dropping the table if it exists can be useful during development
-- Uncomment the next line if you want this behavior
-- DROP TABLE IF EXISTS `yourls_log`;

CREATE TABLE `yourls_log` (
  `click_id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `click_time` datetime NOT NULL,
  `shorturl` varchar(200) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  `referrer` varchar(200) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT NULL,
  `user_agent` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL,
  `ip_address` varchar(41) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL,
  `country_code` char(2) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT NULL,
  PRIMARY KEY (`click_id`),
  KEY `shorturl` (`shorturl`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Note:
-- - `shorturl` matches the collation of `keyword` in `yourls_url`.
-- - `country_code` is nullable, as GeoIP lookup might not always be available/successful.
-- - Added an index on `shorturl` for faster lookup of logs for a specific link.

-- Adding the YOURLS options table
-- DROP TABLE IF EXISTS `yourls_options`;

CREATE TABLE `yourls_options` (
  `option_id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `option_name` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL DEFAULT '',
  `option_value` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL,
  PRIMARY KEY (`option_id`,`option_name`),
  UNIQUE KEY `option_name` (`option_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Note:
-- - This table stores configuration options, similar to WordPress options.
-- - `next_keyword` option will be stored here for sequential keyword generation. 