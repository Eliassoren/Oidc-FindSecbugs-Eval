package firebase;

import java.util.concurrent.Executor;
import java.util.concurrent.Future;

public interface ApiFuture<V> extends Future<V> {
    void addListener(Runnable var1, Executor var2);
}