import re


def is_canonical_version(version: str) -> bool:
    """Test is given version follow PEP440 canonical version form"""
    epoch_regex = r"([1-9][0-9]*!)?"
    major_regex = r"(0|[1-9][0-9]*)"
    minor_bug_fix_regex = r"(\.(0|[1-9][0-9]*))*"
    pre_release_regex = r"((a|b|rc)(0|[1-9][0-9]*))?"
    post_regex = r"(\.post(0|[1-9][0-9]*))?"
    dev_regex = r"(\.dev(0|[1-9][0-9]*))?"
    return (
        re.match(
            (
                rf"^{epoch_regex}{major_regex}{minor_bug_fix_regex}"
                rf"{pre_release_regex}{post_regex}{dev_regex}$"
            ),
            version,
        )
        is not None
    )
