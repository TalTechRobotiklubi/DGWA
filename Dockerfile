FROM python:3.12

# Set the working directory
WORKDIR /app

# Copy the requirements file
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY . .

# Make entrypoint.sh executable
RUN chmod +x entrypoint.sh

# Expose the port
EXPOSE 5000

# Run entrypoint.sh
ENTRYPOINT ["./entrypoint.sh"]
