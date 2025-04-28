# Use an official Python runtime as a parent image
FROM python:3.10-slim

# Set the working directory in the container
WORKDIR /app

# Install uv for faster dependency installation
RUN pip install uv

# Copy the requirements file into the container at /app
COPY requirements.txt .

# Install any needed packages specified in requirements.txt using uv
# Also install gunicorn (already added to requirements.txt)
RUN uv pip install --system --no-cache-dir -r requirements.txt

# Copy the application source code into the container at /app/src
# Assuming your app code is in a 'src' directory
COPY ./src /app/src

# Make port 5000 available to the world outside this container
EXPOSE 5000

# Define environment variable (optional, can be overridden by Docker Compose)
ENV FLASK_APP=src.app:app

# Run the app using gunicorn
# Bind to 0.0.0.0 to be accessible from outside the container
# The number of workers can be adjusted based on resources
CMD ["gunicorn", "--workers", "2", "--bind", "0.0.0.0:5000", "src.app:app"] 