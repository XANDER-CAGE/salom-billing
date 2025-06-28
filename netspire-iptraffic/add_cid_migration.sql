-- Migration to add CID (Calling-Station-Id / MAC address) field to iptraffic_sessions table
-- Run this script if you have an existing database

ALTER TABLE iptraffic_sessions ADD COLUMN cid VARCHAR(128);

-- Add comment for the field
COMMENT ON COLUMN iptraffic_sessions.cid IS 'Calling-Station-Id (MAC address) from RADIUS'; 