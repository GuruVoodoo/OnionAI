# OnionAI DockerFile
# Set the base image
FROM ubuntu:latest

# Set the author label
LABEL authors="Jon Snow"

# Update system packages
RUN apt-get update && apt-get upgrade -y

# Install Rust, cmake, g++, and other required packages
RUN apt-get install -y \
    curl \
    git \
    make \
    tar \
    pkg-config \
    openssl \
    libsodium-dev \
    libncurses5-dev \
    libreadline-dev \
    zlib1g-dev \
    gcc \
    g++ \
    gdb \
    cmake \
    libpcre3-dev

# Set the working directory
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

# Build the application
#RUN cargo build --release

# Run the command to start the app when the container launches
#CMD ["/app/target/release/your_binary_name"]
