package hashsnap.login.entity;

// Role Enum
public enum Role {
    USER("ROLE_USER", "일반 사용자"),
    ADMIN("ROLE_ADMIN","관리자");

    private final String authority;
    private final String description;

    Role(String authority, String description){
        this.authority = authority;
        this.description = description;
    }

    public String getAuthority(){
        return authority;
    }

    public String getDescription() {
        return description;
    }
}
