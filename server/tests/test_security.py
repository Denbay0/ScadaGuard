from app.security import (
    create_agent_token,
    hash_agent_token,
    hash_password,
    parse_bearer_header,
    verify_password,
)


def test_agent_token_is_random_and_hashable() -> None:
    first, first_hash, prefix = create_agent_token()
    second, second_hash, _ = create_agent_token()
    assert first.startswith("sg_")
    assert first != second
    assert first_hash == hash_agent_token(first)
    assert first_hash != second_hash
    assert prefix == first[:12]


def test_password_hash_does_not_contain_password() -> None:
    password_hash = hash_password("correct horse battery staple")
    assert "correct horse" not in password_hash
    assert verify_password("correct horse battery staple", password_hash)
    assert not verify_password("wrong", password_hash)


def test_bearer_header_parser_is_strict() -> None:
    assert parse_bearer_header("Bearer token") is not None
    assert parse_bearer_header("Basic token") is None
    assert parse_bearer_header(None) is None
