#!/bin/bash
PROJECT_NAME="go-owcrypt"

# vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv Input username of CI
read -p "Please input your username of CI platform: " USERNAME
echo "Your username of CI: $USERNAME"
echo "Current project name : $PROJECT_NAME"
while [ "$USERNAME" == "" ]
do
        read -p "Please input your username of CI platform: " USERNAME
        echo "Your username of CI: $USERNAME"
        echo "Current project name : $PROJECT_NAME"
done
# ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

# vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv Init SSH config
echo "Host *
    KexAlgorithms +diffie-hellman-group1-sha1
" > ~/.ssh/config

if [ $? != 0 ]; then
	echo ""
	echo "Failed!"
	exit
fi
# ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

# vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv Load hooks
mkdir -p .git/hooks
gitdir=$(git rev-parse --git-dir); scp -p -P 29418 $USERNAME@47.107.241.104:hooks/commit-msg ${gitdir}/hooks/

if [ $? != 0 ]; then
	echo ""
	echo "Failed!"
	exit
fi
# ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

# vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv Edit .git/config
git config remote.gerrit.url ssh://$USERNAME@47.107.241.104:29418/$PROJECT_NAME.git
git config remote.gerrit.fetch +refs/heads/*:refs/remotes/gerrit/*
git config remote.gerrit.push refs/heads/*:refs/for/*

if [ $? != 0 ]; then
	echo ""
	echo "Failed!"
	exit
fi
# ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

echo ""
echo "Success!"

