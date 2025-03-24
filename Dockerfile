# Use OpenJDK 17 as base image
FROM openjdk:17-jdk-slim

# Set working directory inside the container
WORKDIR /app

# Copy everything from your project to the container
COPY . .

# Build the application using Maven
RUN ./mvnw clean package -DskipTests

# Expose the port your Java app runs on (usually 8080)
EXPOSE 8080

# Start the application
CMD ["java", "-jar", "target/Bankingsys-1.0-SNAPSHOT.jar"]
