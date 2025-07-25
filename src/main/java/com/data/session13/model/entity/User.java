package com.data.session13.model.entity;

package com.b910.model.entity;

import jakarta.persistence.*;
import lombok.*;

import java.util.Set;
import java.util.UUID;

@Entity
@Table(name = "users")
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Builder
public class User{
    @Id
    @GeneratedValue
    private UUID id;

    @Column(unique = true, nullable = true, length = 100)
    private String username;

    @Column(nullable = false, length = 100)
    private String password;

    @Column(nullable = false, length = 100, unique = true)
    private String email;

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(name = "user_roles", joinColumns = @JoinColumn(name = "user_id"), inverseJoinColumns = @JoinColumn(name = "role_id"))
    private Set<Role> roles;
    @Column(nullable = false)
    private boolean status;
}