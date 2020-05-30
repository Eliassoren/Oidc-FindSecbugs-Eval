package oidc.otherexamples;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;

import java.time.Duration;
import java.util.List;

public class PermissionService {

    private final LoadingCache<String, List<SecurityContext.Permission>> permissionsCache;


    public PermissionService(PermissionDBService permissionDB, int maxCacheSize, Duration expireTime) {
        permissionsCache = CacheBuilder.newBuilder()
                .maximumSize(maxCacheSize)
                .expireAfterAccess(expireTime)
                .build(CacheLoader.from(permissionDB::permissionsForUser));
    }

    public List<SecurityContext.Permission> permissionsForUser(String username) {
        return permissionsCache.getUnchecked(username);
    }

    public void invalidateCache() {
        permissionsCache.invalidateAll();
    }
}