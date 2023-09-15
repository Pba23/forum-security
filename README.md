# 🗨️ FORUM

## INTRODUCTION

This project aims to create a web forum that allows users to communicate with each other, create posts, comment on posts, and interact with the content through likes and dislikes. The forum will be implemented using Go and SQLite for data storage. The project will be divided into several modules, each with specific objectives and functionalities.

## PROJECT MODULES

1. **forum**: Implement the core functionalities of the web forum, such as user registration, login, post creation, commenting, liking/disliking, and post filtering.
2. **authentication**: Integrate authentication means for users to register and login using Google and Github authentication tools.
3. **forum-image-upload**: Allow registered users to create posts with images and handle image validation and storage.
4. **security**: Enhance forum security by implementing HTTPS, Rate Limiting, and password encryption.
5. **forum-moderation**: Implement a moderation system with user access levels and moderation functionalities.
6. **forum-advanced-features**: Add advanced features like notifications, activity tracking, and post/comment editing/removal.

## INSTRUCTIONS

- The project will use Go for server-side development and SQLite for data storage.
- All frontend development should be done using pure HTML/CSS without any frontend frameworks.
- Ensure proper error handling and HTTP status code management throughout the project.
- Write unit tests for critical functionalities to ensure reliability.
- Dockerize the forum application to facilitate deployment.

## GETTING STARTED

Follow these steps to set up and run the web forum:

1. Clone the repository:
   ```
   git clone <repository-url>
   cd forum
   ```

2. Install dependencies:
   ```
   go mod tidy
   ```

3. Build the application:
   ```
   go build
   ```

4. Run the application:
   ```
   ./forum
   ```

5. Access the forum in your web browser at `http://localhost:8080`.

## AUTHORS

- @pba
- @papgueye
- @lomalack
- @serignmbaye
