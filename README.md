# Authorization

## Learning Goals

- Set up authorization in the project.

## Introduction

As we discussed, "Authentication" (also referred to as AuthN) is the process of
verifying that a user is who they say there are. Now that we know our users are
who they say they are, we can also (optionally) give different users access to
different resources and functionality. This is called "Authorization" (also
referred to as AuthZ) and is what we'll discuss in this section.

## Authorization Setup

In our web application, we currently 2 URLs: `/hello` and `/status`. Let's say
that we want any authenticated user to be able to access the `/hello` URL, while
we only want "adminstrative" users to access the `/status` URL, because we
consider the status information for our application to be sensitive information.

We can use the "request matching" functionality we used for AuthN, but instead
of coupling it with `authenticated()` or `permitAll()` like we did in the
previous section, we're going to couple it with the `hasAuthority()` method and
pass it the name of the "authority" that we want to restrict access to.

But first, let's modify our `UserDetailsService` so that our 2 users have
different authority:

```java
    @Bean
    public UserDetailsService userDetailsService() {
        InMemoryUserDetailsManager userDetailService = new InMemoryUserDetailsManager();

        UserDetails user1 = User.withUsername("user")
                .password(passwordEncoder().encode("test"))
                .authorities("read")
                .build();
        userDetailService.createUser(user1);

        UserDetails adminUser1 = User.withUsername("admin")
                .password(passwordEncoder().encode("test"))
                .authorities("admin")
                .build();
        userDetailService.createUser(adminUser1);

        return userDetailService;
    }
```

As you can see, we have given our `user1` the "read" authority and our
`adminUser1` the "admin" authority. Note that these 2 authorities are arbitrary
and only matter in that they will need to match with the AuthZ rules we're about
to set in our `SecurityConfiguration` `configure` method:

```java
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/status")
                .hasAuthority("admin");

        http.authorizeRequests()
                .anyRequest()
                .authenticated()
                .and()
                .formLogin();

    }
```

Restart your application now and observe that you will only be able to access
the `/admin` URL with the "admin" user.

As with authentication rules, authorization rules can also be chained and should
be ordered from most specific to least specific.

In our example, we could require the "admin" authority for both the `/status`
and `/hello` URLs with the following `configure()` method:

```java
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/status")
                .hasAuthority("admin")
                .antMatchers("/hello")
                .hasAuthority("admin");

        http.authorizeRequests()
                .anyRequest()
                .authenticated()
                .and()
                .formLogin();

    }
```

When you change the rules as above, you will notice that your acceptance and
integration tests do not pass anymore. The reason for this is that the
`@WithMockUser` annotation that we used for the methods that test the `/hello`
endpoint did not specify an authority level - therefore they do not pass our new
validation rules.

Let's address that:

```java
package com.flatiron.spring.FlatironSpring;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class HelloControllerAcceptanceTest {

    @Autowired
    private MockMvc mockMvc;

    @WithMockUser(username = "fakeuser", authorities = "admin") // added authorities to our mock user
    @Test
    void shouldGreetDefault() throws Exception {
        mockMvc.perform(get("/hello"))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Hello Stephanie")));
    }

    @WithMockUser(username = "fakeuser", authorities = "admin") // added authorities to our mock user
    @Test
    void shouldGreetByName() throws Exception {
        String greetingName = "Jamie";
        mockMvc.perform(get("/hello")
                        .param("targetName", greetingName))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Hello " + greetingName)));
    }
}
```

As you can see, we have now added the `authorities` property to our
`@WithMockUser` annotation, which injects the authority values we specify to the
mock user used by the Spring Testing framework. Apply the same change ton your
integration tests and your entire test suite should pass again.

## Conclusion

We have set up authorization in this lesson. Any production app will likely have
some form of authentication and authorization. In the next lesson, we will look
at how to use existing services to create auth flows.
