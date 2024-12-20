# Base image: Use Node.js base image
FROM rust:bookworm

# Create a non-root user
RUN useradd -ms /bin/bash msfuser

# Install necessary tools and dependencies
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    build-essential \
    git \
    python3 \
    apt-transport-https \
    ca-certificates

# Install nvm
RUN curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.1/install.sh | bash

# Set environment variables for nvm
ENV NVM_DIR=/root/.nvm
ENV PATH=$NVM_DIR/versions/node/v20.17.0/bin:$PATH

# Install a compatible Node.js version and npm
RUN bash -c ". $NVM_DIR/nvm.sh && nvm install 20.17.0 && nvm alias default 20.17.0 && nvm use default && npm install -g npm@9.8.1"

# Install additional dependencies
RUN apt-get install -y \
    libpcap-dev \
    libssl-dev \
    zlib1g-dev \
    ruby-full \
    arp-scan \
    nmap \
    dnsrecon \
    postgresql postgresql-contrib \
    dnsutils \
    iputils-ping \
    libutempter-dev \
    cmake

# Install Metasploit
RUN curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > /tmp/msfinstall && \
    chmod 755 /tmp/msfinstall && \
    /tmp/msfinstall

# Add Metasploit binaries to the PATH
ENV PATH=$PATH:/opt/metasploit-framework/bin

# Set working directory
WORKDIR /msf

# Copy the application files to the container
COPY . .

# Switch to root to run npm install with correct permissions
USER root

# Run npm install as root to avoid permission issues
COPY package.json /msf/
RUN npm update
RUN npm install

# Install Node.js dependencies
RUN npm install --build-from-source --no-optional

# Rebuild node-pty to ensure native modules match the Docker architecture
RUN npm rebuild node-pty --build-from-source

# Install cargo
RUN apt-get install -y cargo

# Ensure that msfuser has ownership of the code directory after installation
RUN chown -R msfuser:msfuser /msf

# Switch back to non-root user
USER msfuser

# Initialize the Metasploit Database
RUN msfdb init && msfdb start

# Expose port for the web or API service
EXPOSE 8081
EXPOSE 8082

# Command to start the Node.js application
CMD ["node", "server.js"]
