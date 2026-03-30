-- Create radiology_coach database for the application
CREATE DATABASE radiology_coach;

-- Grant all privileges to radcoach user
GRANT ALL PRIVILEGES ON DATABASE radiology_coach TO radcoach;

-- Connect to radiology_coach to set it as default
\c radiology_coach;

-- Grant schema privileges
GRANT ALL ON SCHEMA public TO radcoach;