-- Sample data for YOURLS Python Adapter database

-- Clear existing data (optional, uncomment if needed for clean testing)
-- DELETE FROM `yourls_log`;
-- DELETE FROM `yourls_url`;

-- Sample URL entries
INSERT INTO `yourls_url` (`keyword`, `url`, `title`, `timestamp`, `ip`, `clicks`) VALUES
('gh', 'https://github.com/', 'GitHub', '2024-01-10 10:00:00', '192.168.1.1', 3),
('blog', 'https://blog.yourls.org/', 'YOURLS Blog', '2024-02-15 11:30:00', '10.0.0.5', 2),
('wiki', 'https://wikipedia.org/', NULL, '2024-03-20 14:05:00', '172.16.0.10', 0),
('demo', 'https://example.com/another-page-for-testing', 'Another Test Page', '2024-04-25 09:15:00', '192.168.1.1', 1),
('python', 'https://www.python.org/', 'Python Official Website', '2024-04-26 16:00:00', '10.0.0.5', 5);

-- Sample Log entries (corresponding to the clicks count above)

-- Logs for 'gh' (3 clicks)
INSERT INTO `yourls_log` (`click_time`, `shorturl`, `referrer`, `user_agent`, `ip_address`, `country_code`) VALUES
('2024-01-11 08:20:05', 'gh', 'https://www.google.com/', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.1000.0 Safari/537.36', '8.8.8.8', NULL),
('2024-01-12 14:05:10', 'gh', 'https://www.google.com/', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Safari/605.1.15', '1.1.1.1', NULL),
('2024-01-15 19:55:00', 'gh', NULL, 'Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Mobile/15E148 Safari/604.1', '8.8.4.4', NULL);

-- Logs for 'blog' (2 clicks)
INSERT INTO `yourls_log` (`click_time`, `shorturl`, `referrer`, `user_agent`, `ip_address`, `country_code`) VALUES
('2024-02-16 09:00:00', 'blog', NULL, 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.1000.0 Safari/537.36', '192.168.1.100', NULL),
('2024-02-18 12:10:30', 'blog', 'https://news.ycombinator.com/', 'Mozilla/5.0 (X11; Linux x86_64; rv:100.0) Gecko/20100101 Firefox/100.0', '10.10.10.10', NULL);

-- Logs for 'demo' (1 click)
INSERT INTO `yourls_log` (`click_time`, `shorturl`, `referrer`, `user_agent`, `ip_address`, `country_code`) VALUES
('2024-04-26 10:00:00', 'demo', 'https://my.example-site.com/test-page', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.1000.0 Safari/537.36', '172.17.0.5', NULL);

-- Logs for 'python' (5 clicks)
INSERT INTO `yourls_log` (`click_time`, `shorturl`, `referrer`, `user_agent`, `ip_address`, `country_code`) VALUES
('2024-04-27 10:00:00', 'python', 'https://duckduckgo.com/', 'Mozilla/5.0 (X11; Linux x86_64; rv:100.0) Gecko/20100101 Firefox/100.0', '1.0.0.1', NULL),
('2024-04-27 11:00:00', 'python', 'https://duckduckgo.com/', 'Mozilla/5.0 (X11; Linux x86_64; rv:100.0) Gecko/20100101 Firefox/100.0', '1.0.0.1', NULL),
('2024-04-28 12:30:00', 'python', NULL, 'Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Mobile/15E148 Safari/604.1', '8.8.8.8', NULL),
('2024-04-29 15:45:10', 'python', 'https://www.google.com/', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.1000.0 Safari/537.36', '192.168.1.101', NULL),
('2024-04-30 08:05:00', 'python', NULL, 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Safari/605.1.15', '1.1.1.1', NULL); 