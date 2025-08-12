# --- Stage 1: Builder ---
# This stage uses a full Python image to build our dependencies.
# It contains all the necessary build tools and compilers.
FROM python:3.11-bookworm AS builder

# Set environment variables to ensure best practices for Python in Docker.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    # Path for the virtual environment
    VENV_PATH="/opt/venv"

# Create the virtual environment.
RUN python3 -m venv $VENV_PATH

# Set the PATH to use the venv's pip and python.
ENV PATH="$VENV_PATH/bin:$PATH"

# Install build dependencies if any were needed (e.g., build-essential).
# For this project, the base image is sufficient.

# Copy the requirements file into the builder stage.
COPY requirements.txt .

# Install the Python dependencies into the virtual environment.
# This layer will be cached as long as requirements.txt doesn't change.
RUN pip install --no-cache-dir -r requirements.txt


# --- Stage 2: Final Image ---
# This stage uses a slim base image, which is much smaller.
# We will copy the built dependencies and source code into this stage.
FROM python:3.11-slim-bookworm AS final

# Set the same environment variables for consistency.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    VENV_PATH="/opt/venv"

# Set the working directory for the application.
WORKDIR /app

# Update OS packages and install curl, which is required for the HEALTHCHECK.
# This is done in a single RUN command to reduce layer size.
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl \
 # Clean up apt cache to keep the image small.
 && rm -rf /var/lib/apt/lists/*

# Create a non-root user and group for the application to run as.
# This is a critical security best practice.
RUN addgroup --system app && adduser --system --ingroup app app

# Copy the virtual environment from the builder stage.
# This gives us all the installed Python packages without any build tools.
COPY --from=builder $VENV_PATH $VENV_PATH

# Copy the application source code into the final image.
# The .dockerignore file will prevent unnecessary files from being copied.
COPY --chown=app:app . .

# Set the PATH to include the virtual environment's binaries.
# This ensures that the 'uvicorn' command uses the one from our venv.
ENV PATH="$VENV_PATH/bin:$PATH"

# Switch to the non-root user.
USER app

# Expose the port the application will run on.
EXPOSE 8000

# Define a healthcheck to ensure the application is running and healthy.
# It uses the /readyz endpoint, which checks dependencies like OPA.
HEALTHCHECK --interval=30s --timeout=3s --retries=5 \
  CMD curl -fsS http://127.0.0.1:8000/readyz >/dev/null || exit 1

# The command to run the application using uvicorn.
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
