cd ..
git add .
read -r -p "Your commit message: " message
git commit -m "$message"
git push