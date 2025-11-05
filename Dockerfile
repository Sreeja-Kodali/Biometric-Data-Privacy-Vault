FROM openjdk:17

WORKDIR /app

COPY . /app

RUN javac src/*.java

EXPOSE 8081

CMD ["java", "-cp", "src", "Main"]
