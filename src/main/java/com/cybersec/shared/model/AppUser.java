package com.cybersec.shared.model;

import jakarta.persistence.*;

@Entity
@Table(name = "app_users")
public class AppUser {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 80) private String username;
    @Column(nullable = false, length = 200)               private String password;
    @Column(nullable = false, length = 30)                private String role;
    @Column(nullable = false)                             private boolean enabled = true;
    @Column(length = 100)                                 private String email;

    public Long getId()       { return id; }
    public String getUsername() { return username; }
    public String getPassword() { return password; }
    public String getRole()   { return role; }
    public boolean isEnabled(){ return enabled; }
    public String getEmail()  { return email; }

    public void setUsername(String v) { this.username = v; }
    public void setPassword(String v) { this.password = v; }
    public void setRole(String v)     { this.role = v; }
    public void setEnabled(boolean v) { this.enabled = v; }
    public void setEmail(String v)    { this.email = v; }

    public static Builder builder() { return new Builder(); }
    public static class Builder {
        private final AppUser u = new AppUser();
        public Builder username(String v) { u.username = v; return this; }
        public Builder password(String v) { u.password = v; return this; }
        public Builder role(String v)     { u.role = v;     return this; }
        public Builder email(String v)    { u.email = v;    return this; }
        public Builder enabled(boolean v) { u.enabled = v;  return this; }
        public AppUser build()            { return u; }
    }
}
