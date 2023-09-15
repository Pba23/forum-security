SELECT
    p.id AS ID,
    p.title AS Title,
    u.username AS AuthorName,
    p.imageURL AS ImageURL,
    p.modifiedDate AS LastEditionDate,
    COALESCE(cmt_counts.comment_count, 0) AS NumberOfComments,
    COALESCE(cmt.commentators, '') AS ListOfCommentator
FROM "post" p
LEFT JOIN "user" u ON p.authorID = u.id
LEFT JOIN (
    SELECT
        c.postID,
        COUNT(c.id) AS comment_count,
        GROUP_CONCAT(u.username) AS commentators
    FROM "comment" c
    JOIN "user" u ON c.authorID = u.id
    GROUP BY c.postID
) cmt_counts ON p.id = cmt_counts.postID
LEFT JOIN (
    SELECT
        c.postID,
        GROUP_CONCAT(u.username) AS commentators
    FROM "comment" c
    JOIN "user" u ON c.authorID = u.id
    GROUP BY c.postID
) cmt ON p.id = cmt.postID
ORDER BY LastEditionDate DESC;

SELECT u.id AS user_id,
       u.username AS user_username,
       COUNT(v.id) AS number_of_likes
FROM "user" u
LEFT JOIN "post" p ON u.id = p.authorID
LEFT JOIN "view" v ON p.id = v.postID
GROUP BY u.id, u.username
ORDER BY (number_of_likes) DESC;

SELECT u.id AS user_id,
       u.username AS user_username,
       COUNT(DISTINCT c.id) + COUNT(DISTINCT v.id) AS number_reaction
FROM "user" u
LEFT JOIN "post" p ON u.id = p.authorID
LEFT JOIN "comment" c ON p.id = c.postID
LEFT JOIN "view" v ON p.id = v.postID AND v.rate != 0
GROUP BY u.id, u.username
ORDER BY number_reaction DESC;

SELECT
    c.postID AS post_id,
    GROUP_CONCAT(DISTINCT u1.avatarURL) AS avatar1,
    GROUP_CONCAT(DISTINCT u2.avatarURL) AS avatar2,
    GROUP_CONCAT(DISTINCT u3.avatarURL) AS avatar3
FROM "comment" c
LEFT JOIN "user" u1 ON c.authorID = u1.id
LEFT JOIN "user" u2 ON c.authorID = u2.id
LEFT JOIN "user" u3 ON c.authorID = u3.id
WHERE c.id IN (
    SELECT id
    FROM "comment"
    WHERE postID = c.postID
    ORDER BY createDate DESC
    LIMIT 3
)
GROUP BY c.postID;

SELECT
    p.id AS post_id,
    p.title AS post_title,
    p.imageURL AS post_image,
    COALESCE(commentators.avatar1, '') AS top_commentator_avatar1,
    COALESCE(commentators.avatar2, '') AS top_commentator_avatar2,
    COALESCE(commentators.avatar3, '') AS top_commentator_avatar3
FROM "post" p
LEFT JOIN (
    SELECT
        c.postID AS post_id,
        GROUP_CONCAT(DISTINCT u1.avatarURL) AS avatar1,
        GROUP_CONCAT(DISTINCT u2.avatarURL) AS avatar2,
        GROUP_CONCAT(DISTINCT u3.avatarURL) AS avatar3
    FROM "comment" c
    LEFT JOIN "user" u1 ON c.authorID = u1.id
    LEFT JOIN "user" u2 ON c.authorID = u2.id
    LEFT JOIN "user" u3 ON c.authorID = u3.id
    WHERE c.id IN (
        SELECT id
        FROM "comment"
        WHERE postID = c.postID
        ORDER BY createDate DESC
        LIMIT 3
    )
    GROUP BY c.postID
) commentators ON p.id = commentators.post_id;

SELECT u.id AS user_id,
       u.username AS user_username,
       p.title AS title,
       c.text AS comment,
       v.rate AS rate
FROM "user" u
LEFT JOIN "post" p ON u.id = p.authorID
LEFT JOIN "comment" c ON p.id = c.postID
LEFT JOIN "view" v ON p.id = v.postID;

-- SELECT u.id AS user_id,
--        u.username AS user_username,
--        COUNT(c.id) AS number_of_comments
-- FROM "user" u
-- LEFT JOIN "post" p ON u.id = p.authorID
-- LEFT JOIN "comment" c ON p.id = c.postID
-- GROUP BY u.id
-- ORDER BY (number_of_comments) DESC
-- LIMIT 3;
-- SELECT u.id AS user_id,
--        u.username AS user_username,
--        COUNT(c.id) AS number_of_comments
-- FROM "user" u
-- LEFT JOIN "post" p ON u.id = p.authorID
-- LEFT JOIN "comment" c ON p.id = c.postID
-- GROUP BY u.id
-- ORDER BY (number_of_comments) DESC
-- LIMIT 3;

SELECT p.id AS post_id,
       COUNT(v.id) AS views_of_the_post
FROM "post" p
LEFT JOIN "view" v on v.postid = p.id
GROUP BY p.id;

SELECT p.id AS post_id,
       COUNT(v.id) AS likes_of_the_post
FROM "post" p
LEFT JOIN "view" v on v.postid = p.id
WHERE v.rate = 1
GROUP BY p.id;

SELECT p.id AS post_id,
       COUNT(v.id) AS dislikes_of_the_post
FROM "post" p
LEFT JOIN "view" v on v.postid = p.id
WHERE v.rate = 2
GROUP BY p.id;

SELECT p.id AS post_id,
FROM "user" u
LEFT JOIN "post" p on u.id= 2;