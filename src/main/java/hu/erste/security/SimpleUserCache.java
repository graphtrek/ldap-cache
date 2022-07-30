package hu.erste.security;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.security.core.userdetails.UserCache;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Cache user details in memory for the time configured
 */
public class SimpleUserCache implements UserCache {

    private static final long TECH_USER_EXPIRY = 365 * 24 * 60 * 60 * 1000L;

    private final int expiryInMs;

    private final ConcurrentMap<String, UserCacheEntry> userMap = new ConcurrentHashMap<>(1);

    public SimpleUserCache(int expiryInMs) {
        this.expiryInMs = expiryInMs;
    }

    @Override
    public UserDetails getUserFromCache(String username) {
        UserCacheEntry entry = userMap.get(username.toLowerCase());
        if (entry == null) {
            return null;
        }
        if (entry.getExpiry() > System.currentTimeMillis()) {
            return entry.getUserDetails();
        }
        removeUserFromCache(username);
        return null;
    }

    @Override
    public void putUserInCache(UserDetails user) {
        userMap.put(user.getUsername().toLowerCase(), new UserCacheEntry(System.currentTimeMillis() + expiryInMs, user));
    }

    public void putTechUserInCache(UserDetails user) {
        userMap.put(user.getUsername().toLowerCase(), new UserCacheEntry(System.currentTimeMillis() + TECH_USER_EXPIRY, user));
    }

    @Override
    public void removeUserFromCache(String username) {
        userMap.remove(username.toLowerCase());
    }

    @Getter
    @AllArgsConstructor
    private static class UserCacheEntry {
        private final Long expiry;
        private final UserDetails userDetails;
    }
}
