-- SQL schema for user-class-diagram
-- Table for 'user'
CREATE TABLE IF NOT EXISTS "user" (
    id VARCHAR PRIMARY KEY,
    username VARCHAR,
    email VARCHAR,
    password TEXT,
    avatarURL VARCHAR,
    role VARCHAR
);
-- Table for 'post'
CREATE TABLE IF NOT EXISTS "post" (
    id VARCHAR PRIMARY KEY,
    title VARCHAR,
    slug VARCHAR,
    description VARCHAR,
    imageURL VARCHAR,
    authorID VARCHAR,
    isEdited BOOLEAN,
    createDate DATE,
    modifiedDate DATE,
    validate BOOLEAN,
    FOREIGN KEY (authorID) REFERENCES user(id)
);
-- Table for 'report'
CREATE TABLE IF NOT EXISTS "report" (
    id VARCHAR PRIMARY KEY,
    authorID VARCHAR,
    reportedID VARCHAR,
    reportedName VARCHAR,
    cause VARCHAR,
    type VARCHAR,
    createDate DATE,
    modifiedDate DATE,
    reported BOOLEAN,
    imageURL VARCHAR,
    FOREIGN KEY (authorID) REFERENCES user(id),
    FOREIGN KEY (reportedID) REFERENCES user(id)
);
-- Table for 'response'
CREATE TABLE IF NOT EXISTS "response" (
    id VARCHAR PRIMARY KEY,
    authorID VARCHAR,
    reportID VARCHAR,
    content TEXT,
    createDate DATE,
    modifiedDate DATE,
    FOREIGN KEY (authorID) REFERENCES user(id),
    FOREIGN KEY (reportID) REFERENCES report(id)
);
-- Table for 'view'
CREATE TABLE IF NOT EXISTS "view" (
    id VARCHAR PRIMARY KEY,
    isBookmarked BOOLEAN,
    rate INT,
    authorID VARCHAR,
    postID VARCHAR,
    FOREIGN KEY (authorID) REFERENCES user(id),
    FOREIGN KEY (postID) REFERENCES post(id)
);
-- Table for 'comment_rate'
CREATE TABLE IF NOT EXISTS "comment_rate" (
    id VARCHAR PRIMARY KEY,
    authorID VARCHAR,
    commentID VARCHAR,
    rate INT,
    FOREIGN KEY (authorID) REFERENCES user(id),
    FOREIGN KEY (commentID) REFERENCES comment(id)
);
-- Table for 'comment'
CREATE TABLE IF NOT EXISTS "comment" (
    id VARCHAR PRIMARY KEY,
    text VARCHAR,
    authorID VARCHAR,
    postID VARCHAR,
    parentID VARCHAR,
    createDate DATE,
    modifiedDate DATE,
    FOREIGN KEY (authorID) REFERENCES user(id),
    FOREIGN KEY (postID) REFERENCES post(id),
    FOREIGN KEY (parentID) REFERENCES comment(id)
);
-- Table for 'post_category'
CREATE TABLE IF NOT EXISTS "post_category" (
    id VARCHAR PRIMARY KEY,
    categoryID VARCHAR,
    postID VARCHAR,
    FOREIGN KEY (categoryID) REFERENCES category(id),
    FOREIGN KEY (postID) REFERENCES post(id)
);
-- Table for 'category'
CREATE TABLE IF NOT EXISTS "category" (
    id VARCHAR PRIMARY KEY,
    name VARCHAR,
    createDate DATE,
    modifiedDate DATE
);
-- Table for 'notification'
CREATE TABLE IF NOT EXISTS "notification" (
    id VARCHAR PRIMARY KEY,
    authorID VARCHAR,
    author_name VARCHAR,
    postID VARCHAR,
    ownerID VARCHAR,
    notif_type VARCHAR,
    slug VARCHAR,
    time VARCHAR,
    Readed BOOLEAN,
    FOREIGN KEY (postID) REFERENCES post(id)
);
-- Table for 'request'
-- TODO: REMOVE DUPLICATED INFOS REQUEST
CREATE TABLE IF NOT EXISTS "request"(
    id VARCHAR PRIMARY KEY,
    authorID VARCHAR,
    time DATE,
    username VARCHAR,
    imageurl VARCHAR,
    role VARCHAR,
    FOREIGN KEY (authorID) REFERENCES user(id)
);