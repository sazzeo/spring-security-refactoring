package nextstep.autoconfigure;

@FunctionalInterface
public interface Customizer<T> {
    void customize(T t);

}

