# SpringBoot JWT with MySQL DB

A simple maven spring boot example to generate jwt which uses MySQL as the database

## Configure Spring Datasource, JPA, App properties
For MySQL
```
spring.datasource.url= jdbc:mysql://localhost:3306/yourdb
spring.datasource.username= yourusername
spring.datasource.password= yourpassword

spring.jpa.properties.hibernate.dialect= org.hibernate.dialect.MySQL5InnoDBDialect
spring.jpa.hibernate.ddl-auto= update
```

## Run following SQL insert statements
```
INSERT INTO roles(name) VALUES('ROLE1');
INSERT INTO roles(name) VALUES('ROLE2');
INSERT INTO roles(name) VALUES('ROLE3');
```

## Run Spring Boot application
```
mvn spring-boot:run
```

