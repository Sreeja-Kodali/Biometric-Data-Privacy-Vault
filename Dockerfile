FROM eclipse-temurin:17-jdk

WORKDIR /app

COPY . /app

RUN javac src/*.java

EXPOSE 8081

CMD ["java", "-cp", "src", "Main"]
