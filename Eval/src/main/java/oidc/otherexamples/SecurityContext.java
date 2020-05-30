package oidc.otherexamples;


import java.security.Principal;
import java.util.List;
import java.util.Set;

import static java.util.Collections.emptyList;
import static java.util.Collections.emptySet;
import static java.util.stream.Collectors.toList;

public class SecurityContext implements javax.ws.rs.core.SecurityContext {

    private static final SecurityContext UNAUTHENTICATED = new SecurityContext("unauthenticated", emptySet(), emptyList());
    private final String uid;
    private final Set<String> roles;
    private final List<Permission> permissions;

    public SecurityContext(String uid,
                           Set<String> roles,
                           List<Permission> permissions) {
        this.uid = uid;
        this.roles = roles;
        this.permissions = permissions;
    }

    public static SecurityContext unauthenticated() {
        return UNAUTHENTICATED;
    }

    @Override
    public Principal getUserPrincipal() {
        return () -> uid;
    }

    @Override
    public boolean isUserInRole(String role) {
        return this.roles.contains(role);
    }

    @Override
    public boolean isSecure() {
        return false;
    }

    @Override
    public String getAuthenticationScheme() {
        return javax.ws.rs.core.SecurityContext.BASIC_AUTH;
    }

    /**
     * @param dataResource - DataResource
     * @return true if {@code DataResource} is not sensitive or user has permissions for the resource.
     */
    public boolean hasAccessToDataResource(DataResource dataResource) {
        return !dataResource.isSensitive() || hasPermission(dataResource);
    }

    /**
     * @param dataResource - DataResource
\     * @param items - check access for these items
     * @return true if {@code DataResource} is not sensitive or user has permissions for the resource in one of the given municipalities and one of the given road categories.
     */
    public boolean hasAccessToDataResource(DataResource dataResource, List<String> items) {
        return permissions.stream()
                .anyMatch(p -> p.dataResourceId == dataResource.getId()
                            && items.stream().anyMatch(str -> str.equals(p.itemCategory)));
    }

    public boolean hasPermission(DataResource resource) {
        return permissions.stream()
                .anyMatch(p -> p.dataResourceId == resource.getId());
    }


    public List<String> permittedItems(DataResource dataResource) {
        return permissions.stream()
                .filter(p -> p.dataResourceId == dataResource.getId())
                .map(p -> p.itemCategory)
                .collect(toList());
    }

    public boolean hasSensitiveLevel(int sensitiveLevel) {
        return this.roles.contains("role=0_role_sensitive" + sensitiveLevel);
    }

    public static class Permission {

        private boolean isSensitive;
        private Integer dataResourceId;
        private String itemCategory;

        public Permission(boolean isSensitive, Integer dataResourceId, String itemCategory) {
            this.isSensitive = isSensitive;
            this.dataResourceId = dataResourceId;
            this.itemCategory = itemCategory;
        }

        public boolean isSensitive() {
            return isSensitive;
        }

        public Integer getDataResourceId() {
            return dataResourceId;
        }

        public String getItemCategory() {
            return itemCategory;
        }
    }
    
    public static class DataResource {
        private Integer id;
        private boolean isSensitive;
        
        
        public DataResource() {
            
        }

        public int getId() {
            return id;
        }

        public boolean isSensitive() {
            return isSensitive;
        }
    }
}
