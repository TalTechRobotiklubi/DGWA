FROM python:3.12-alpine

# Set the working directory
WORKDIR /app

# Copy the requirements file
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY . .

# Run entrypoint.sh
ENTRYPOINT ["./entrypoint.sh"]
