package nextstep.app.domain;

import java.util.List;
import java.util.Optional;

public interface MemberRepository {
    Optional<Member> findByEmail(String email);

    List<Member> findAll();

    void deleteAll();

    Member save(Member member);
}
