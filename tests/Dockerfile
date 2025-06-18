FROM ubuntu:22.04

# Install necessary dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    clang \
    libcriterion-dev

# Set up working directory
WORKDIR /app

# Copy the source code to the working directory
COPY ../. .

# Compile the source code
RUN clang -g -I./libft -I./include -o test \
    src/hash/md5.c \
    src/hash/sha256.c \
    src/base64.c \
    tests/base64_tests.c \
    tests/hash_tests.c \
    -lcriterion -L./libft/build -lft

# Run the tests
CMD ["./test"]
