# Code Along: Authorization

## Learning Goals

- Set up authorization in the project.

## Introduction

As we discussed, "Authentication" (also referred to as AuthN) is the process of
verifying that a user is who they say there are. Now that we know our users are
who they say they are, we can also (optionally) give different users access to
different resources and functionality. This is called "Authorization" (also
referred to as AuthZ) and is what we'll discuss in this section.

## Authorization Setup

In our web application, we currently have 2 URLs: `/hello` and `/status`. Let's
say that we want any authenticated user to be able to access the `/hello` URL,
while we only want "administrative" users to access the `/status` URL, because
we consider the status information for our application to be sensitive
information.

In order to accomplish this, we need to discuss the differences between
authorities and roles. **Authorities** specify the action we want an end user to
have. These are individual privileges that could include reading, writing, or
deleting. **Roles** encompass various authorities to specify a group of users
with a set of privileges. For example, we could have an admin role, a manager
role, or just a general user role.

Let's go back to pgAdmin4 and open up the `security_demo` database we created
in the last lesson. We'll modify the schema to include some roles for our
`users` table and then add two users to test with. Consider the following ER
diagram that we will be modeling:

![security-demo-er-diagram](https://curriculum-content.s3.amazonaws.com/spring-mod-2/authorization/security-demo-er-diagram.png)

Notice that users can have many authorities and authorities can belong to many
users. To properly implement this many-to-many relationship, we'll create the
`user_authorities` table that will have a composite primary key with the user ID
and the authority ID.

In the Query Tool, copy the following to create the `users`, `authorities`, and
`user_authorities` table along with two test users, an authority, and a
user_authority entry:

```postgresql
DROP TABLE IF EXISTS user_authorities;
DROP TABLE IF EXISTS authorities;
DROP TABLE IF EXISTS users;

CREATE TABLE users (
  id INTEGER PRIMARY KEY,
  username TEXT NOT NULL,
  password TEXT NOT NULL
);

CREATE TABLE authorities (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL
);

CREATE TABLE user_authorities (
  user_id INTEGER,
  authority_id INTEGER,
  PRIMARY KEY (user_id, authority_id),
  CONSTRAINT user_fk FOREIGN KEY (user_id) REFERENCES users (id)
    ON DELETE CASCADE,
  CONSTRAINT authority_fk FOREIGN KEY (authority_id) REFERENCES authorities (id)
    ON DELETE CASCADE
);

INSERT INTO users(id, username, password) VALUES(1, 'mary', 'test');
INSERT INTO users(id, username, password) VALUES(2, 'admin', 'test');
INSERT INTO authorities(id, name) VALUES(1, 'read');
INSERT INTO authorities(id, name) VALUES(2, 'admin');
INSERT INTO user_authorities(user_id, authority_id) VALUES(1, 1);
INSERT INTO user_authorities(user_id, authority_id) VALUES(2, 2);
```

Execute the query and then run the following statements individually to ensure
the users, authorities, and user authorities have been properly persisted to the
database table:

```postgresql
SELECT * FROM users;
SELECT * FROM authorities;
SELECT * FROM user_authorities;
```

Now that we have updated our database to handle authorization, we need to update
our application. In the `entity` package, create a `Authority` class:

```java
package com.example.springsecuritydemo.entity;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.*;
import java.util.HashSet;
import java.util.Set;

@Entity
@Getter
@Setter
@NoArgsConstructor
@Table(name = "authorities")
public class Authority {

    @Id
    @GeneratedValue
    private int id;

    private String name;

    @ManyToMany(mappedBy = "authorities")
    private Set<User> users = new HashSet<>();
}

```

Notice that we need to define the relationship between the authorities and the
users table. Note: In the last module, we saw how we could use the `@OneToMany`
and `@ManyToOne` annotations when mapping a one-to-many relationship in Spring.
We could choose to do the same here, but that would require us to create a user
authority entity. Instead, we'll make use of the `@ManyToMany` annotations - just
like we saw when introducing JPA for the first time in a couple of modules back.

Since we are defining the many-to-many relationship, we'll need to modify the
`User` class as well. Add the following `authorites` field to the `User` class:

```java
    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(name = "user_authorities",
        joinColumns = @JoinColumn(name = "user_id"),
        inverseJoinColumns = @JoinColumn(name = "authority_id"))
private Set<Authority> authorities = new HashSet<>();
```

As a review:

- The `FetchType.EAGER` lets Hibernate know to get all elements of the
  relationship when fetching the data.
- The `@JoinTable` annotation specifies the joined table, or the table that is
  the product of the many-to-many relationship.
- The `joinColumns` specifies the column that this table is linked to while the
  `inverseJoinColumns` specifies the other column that the table is linked to.
  - In this case, in the `User` entity, the `joinColumns` is the `user_id` since
    that is how this table and the `user_authorities` table is joined.
  - The `inverseJoinColumns` assigns the column of the other table related to
    the associated entity, or in this case, the `authorities` table. The
    foreign key that links these tables together is the `authority_id`, so
    that will be specified as the `inverseJoinColumns`.

Now that we have our entities define, what do we do now?

We need to define the authority that the users have! Remember in the last lesson
we said we would come back to the `getAuthorities()` method in our `UserWrapper`
class? It's time to do so!

Now that we have our authority entity, we can use this in the `getAuthorities()`
method... but there is one catch. We need to return a collection of
`GrantedAuthoriy` instances. So we'll use the same design pattern we did in the
last lesson which is to create a wrapper class that encompasses an `Authority`
instance and implements the `GrantedAuthority` interface. Within the `entity`
package, create a `AuthorityWrapper` class that implements the
`GrantedAuthority` interface:

```java
package com.example.springsecuritydemo.entity;

import org.springframework.security.core.GrantedAuthority;

public class AuthorityWrapper implements GrantedAuthority {
    
    private final Authority authority;
    
    public AuthorityWrapper(Authority authority) {
        this.authority = authority;
    }
    
    @Override
    public String getAuthority() {
        return authority.getName();
    }
}
```

In this class, we'll need to override the `getAuthority()` method. We can do
this by returning the authority's name.

Now let's go back to our `UserWrapper` class and look at the `getAuthorities()`
method again:

```java
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(() -> "read");
    }
```

We'll modify this method to reflect our authorities stored in our database that
are associated with our user. Consider the following edits to this method:

```java
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return user.getAuthorities().stream().map(AuthorityWrapper::new).collect(Collectors.toList());
    }
```

We're almost done! But now we need to change our `filterChain()` method just
slightly in the `SecurityConfiguration` class to add authorization!

We can use the "request matching" functionality we used for AuthN, but instead
of coupling it with `authenticated()` or `permitAll()` like we did in the
previous section, we're going to couple it with the `hasAuthority()` method and
pass it the name of the "authority" that we want to restrict access to.

If we remember, when inserting new data into the database, we gave the user
`mary` the `read` authority but the `admin` user an `admin` authority. We only
want the `admin` to be able to access our `/status` endpoint, but we'll still
leave the `/hello` endpoint public so anyone can access the greeting message.

Modify the `filterChain()` method as such:

```java
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity.httpBasic().and().authorizeRequests().antMatchers("/status").hasAuthority("admin");
        httpSecurity.httpBasic().and().authorizeRequests().antMatchers("/hello").permitAll();
        httpSecurity.httpBasic().and().authorizeRequests().anyRequest().authenticated();
        return httpSecurity.build();
    }
```

So what did we do here? We added the line
`httpSecurity.httpBasic().and().authorizeRequests().antMatchers("/status").hasAuthority("admin");`
to say that in order to access this endpoint, the authenticated user _must_ have
an admin authority. If the user is not authenticated and/or does not have the
admin authority attached to it, then we will not be able to reach it.

As with authentication rules, authorization rules can also be chained and should
be ordered from most specific to least specific.

Let's test this out! Open up Postman and start up the application.

We'll start off by choosing the "No Auth" type in the "Authorization" tab in
Postman and sending the "http://localhost:8080/hello?name=mary" GET request URL
to ensure that it still works without having to be authenticated:

![postmnan-no-auth](https://curriculum-content.s3.amazonaws.com/spring-mod-2/authentication/postman-no-authentication.png)

Now let's try to hit the "http://localhost:8080/status" endpoint without any
authentication.

![postman-401-unauthorized](https://curriculum-content.s3.amazonaws.com/spring-mod-2/authentication/postman-unauthorized.png)

Everything is working great still! We'll turn on the "Basic Auth" now and enter
the credentials for `mary` while hitting the "/status" endpoint. We should be
forbidden from seeing the endpoint with this user:

![postman-403-forbidden](https://curriculum-content.s3.amazonaws.com/spring-mod-2/authorization/postman-forbidden.png)

If we enter in the `admin` user credentials and try to hit the "/status"
endpoint, we should now be able to see the message since the `admin` user has
the `admin` authority attached to it:

![postman-admin-authorization](https://curriculum-content.s3.amazonaws.com/spring-mod-2/authorization/postman-admin-authorization.png)

## Code Check

Check the project structure and code in each class to ensure your code matches
what was covered in this lesson.

### Project Structure

```text
├── HELP.md
├── mvnw
├── mvnw.cmd
├── pom.xml
└── src
    ├── main
    │   ├── java
    │   │   └── com
    │   │       └── example
    │   │           └── springsecuritydemo
    │   │               ├── SpringSecurityDemoApplication.java
    │   │               ├── config
    │   │               │   └── SecurityConfiguration.java
    │   │               ├── controller
    │   │               │   └── DemoController.java
    │   │               ├── entity
    │   │               │   ├── Authority.java
    │   │               │   ├── AuthorityWrapper.java    
    │   │               │   ├── User.java
    │   │               │   └── UserWrapper.java
    │   │               ├── repository
    │   │               │   └── UserRepository.java
    │   │               └── service
    │   │                   └── UserService.java
    │   └── resources
    │       ├── application.properties
    │       ├── static
    │       └── templates
    └── test
        └── java
            └── org
                └── example
                    └── springsecuritydemo
                        └── SpringSecurityDemoApplicationTests.java
```

### Authority.java

```java
package com.example.springsecuritydemo.entity;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.*;
import java.util.HashSet;
import java.util.Set;

@Entity
@Getter
@Setter
@NoArgsConstructor
@Table(name = "authorities")
public class Authority {

    @Id
    @GeneratedValue
    private int id;

    private String name;

    @ManyToMany(mappedBy = "authorities")
    private Set<User> users = new HashSet<>();
}
```

### User.java

```java
package com.example.springsecuritydemo.entity;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.*;
import java.util.HashSet;
import java.util.Set;

@Entity
@Getter
@Setter
@NoArgsConstructor
@Table(name = "users")
public class User {

    @Id
    @GeneratedValue
    private int id;

    private String username;

    private String password;

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(name = "user_authorities",
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "authority_id"))
    private Set<Authority> authorities = new HashSet<>();
}
```

### AuthorityWrapper.java

```java
package com.example.springsecuritydemo.entity;

import org.springframework.security.core.GrantedAuthority;

public class AuthorityWrapper implements GrantedAuthority {

    private final Authority authority;

    public AuthorityWrapper(Authority authority) {
        this.authority = authority;
    }

    @Override
    public String getAuthority() {
        String name = authority.getName();
        return authority.getName();
    }
}
```

### UserWrapper.java

```java
package com.example.springsecuritydemo.entity;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

public class UserWrapper implements UserDetails {

    private final User user;

    public UserWrapper(User user) {
        this.user = user;
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    @Override
    public String getPassword() {
        // We'll need to encode the user's password before we return it
        return new BCryptPasswordEncoder().encode(user.getPassword());
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return user.getAuthorities().stream().map(AuthorityWrapper::new).collect(Collectors.toList());
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
```

### SecurityConfiguration.java

```java
package com.example.springsecuritydemo.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfiguration {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity.httpBasic().and().authorizeRequests().antMatchers("/status").hasAuthority("admin");
        httpSecurity.httpBasic().and().authorizeRequests().antMatchers("/hello").permitAll();
        httpSecurity.httpBasic().and().authorizeRequests().anyRequest().authenticated();
        return httpSecurity.build();
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
```

### Other classes

All the other classes in the `spring-security-demo` project remain unchanged
from the last lesson.

## Conclusion

We have set up authorization in this lesson. Any production app will likely have
some form of authentication and authorization.

## References

- [Spring Security Fundamentals - Lesson 2 - Managing Users](https://youtu.be/dFvbHZ8CuKM)
- [Baeldung: Granted Authority Versus Role in Spring Security](https://www.baeldung.com/spring-security-granted-authority-vs-role)
- [Entity Mappings: Introduction to JPA Fetch Types](https://thorben-janssen.com/entity-mappings-introduction-jpa-fetchtypes/#FetchTypeEAGER_8211_Fetch_it_so_you8217ll_have_it_when_you_need_it)
- [Hibernate Bidirectional Mapping Example with @JoinTable Annotation](https://www.concretepage.com/hibernate/hibernate-bidirectional-mapping-example-with-jointable-annotation)
- [BezKoder: Spring Boot, Spring Security, PostgreSQL: JWT Authentication Example](https://www.bezkoder.com/spring-boot-security-postgresql-jwt-authentication/)
