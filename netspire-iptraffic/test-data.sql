
-- Fill up schema for testing purpose

INSERT INTO currencies (id, short_name, name, description) VALUES(1, '$', 'USD', 'United States dollar');

INSERT INTO plans(name, code) VALUES('Standard traffic plan', 'Starter');
INSERT INTO plans(name, code) VALUES('Unlimited 512 Kbit', 'Unlimited 512');
INSERT INTO plans(name, code) VALUES('Unlimited 1024 kbit ', 'Unlimited 1024');

INSERT INTO radius_replies(name, description) VALUES('Acct-Interim-Interval', 'This attribute indicates the number of seconds between each interim update in seconds for this specific session');
INSERT INTO radius_replies(name, description) VALUES('Framed-IP-Address', 'This attribute indicates the address to be configured for the user');
INSERT INTO radius_replies(name, description) VALUES('Service-Type', 'This attribute indicates the type of service the user has requested, or the type of service to be provided');
INSERT INTO radius_replies(name, description) VALUES('Framed-Protocol', 'This attribute indicates the framing to be used for framed access');
INSERT INTO radius_replies(name, description) VALUES('Netspire-Framed-Pool', 'This attribute indicates the pool of IP addresses that need to use');
INSERT INTO radius_replies(name, description) VALUES('Netspire-Upstream-Speed-Limit', 'This attribute indicates the UpStream speed limit');
INSERT INTO radius_replies(name, description) VALUES('Netspire-Downstream-Speed-Limit', 'This attribute indicates the DownStream speed limit');
INSERT INTO radius_replies(name, description) VALUES('Netspire-Allowed-NAS', 'This attribute indicates the NAS identifier to which the user may connect');

INSERT INTO assigned_radius_replies(target_id, target_type, radius_reply_id, value) VALUES(1, 'Account', 1, '65');
INSERT INTO assigned_radius_replies(target_id, target_type, radius_reply_id, value) VALUES(1, 'Account', 3, '2'); -- value is Framed-User
INSERT INTO assigned_radius_replies(target_id, target_type, radius_reply_id, value) VALUES(1, 'Account', 4, '1'); -- value is PPP

-- Tariff's radius replies
INSERT INTO assigned_radius_replies(target_id, target_type, radius_reply_id, value) VALUES(2, 'Plan', 7, '512');
INSERT INTO assigned_radius_replies(target_id, target_type, radius_reply_id, value) VALUES(2, 'Plan', 6, '64');
INSERT INTO assigned_radius_replies(target_id, target_type, radius_reply_id, value) VALUES(3, 'Plan', 7, '1024');
INSERT INTO assigned_radius_replies(target_id, target_type, radius_reply_id, value) VALUES(3, 'Plan', 6, '128');
