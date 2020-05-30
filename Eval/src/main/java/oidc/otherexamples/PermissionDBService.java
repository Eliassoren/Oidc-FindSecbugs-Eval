package oidc.otherexamples;

import java.util.Arrays;
import java.util.List;

public class PermissionDBService {

    public List<SecurityContext.Permission> permissionsForUser(String user) {

        return Arrays.asList(new SecurityContext.Permission(true, 1, "cat"),
                             new SecurityContext.Permission(true, 1, "cat2")
                            );
    }

}