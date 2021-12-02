# Synapse Domain Rule Checker

A module to prevent invites and joins to Matrix rooms by checking the involved server(s)'
domain.


## Installation

From the virtual environment that you use for Synapse, install this module with:
```shell
pip install synapse-domain-rule-checker
```
(If you run into issues, you may need to upgrade `pip` first, e.g. by running
`pip install --upgrade pip`)

Then alter your homeserver configuration, adding to your `modules` configuration:
```yaml
modules:
  - module: synapse_domain_rule_checker.DomainRuleChecker
    config:
      # A mapping describing which servers a server can invite into a room.
      # Default is any server can invite any other server.
      domain_mapping:
        "inviter_domain": [ "invitee_domain_permitted", "other_domain_permitted" ]
        "other_inviter_domain": [ "invitee_domain_permitted" ]

      # Whether an invite should be allowed through if the inviting server doesn't appear
      # in the domain_mapping.
      # Required.
      can_invite_if_not_in_domain_mapping: false

      # Whether a user on this server needs to be invited to be allowed into a room,
      # regardless of the room's settings.
      # Defaults to false.
      can_only_join_rooms_with_invite: false

      # Whether a user on this server can only invite when creating a room.
      # Default is false.
      can_only_invite_during_room_creation: false

      # List of servers that can't be invited to rooms that have been published to the
      # public room directory. This setting only really works in a closed federation in
      # which every server agrees on the list.
      # Defaults to all servers being allowed.
      domains_prevented_from_being_invited_to_published_rooms: []

      # Whether a local user can invite another user using a third-party identifier (e.g.
      # an email address).
      # Defaults to true.
      can_invite_by_third_party_id: true
```

Note that you need to consider invites between two local users when defining values for
`domain_mapping` and `domains_prevented_from_being_invited_to_published_rooms`.

## Development

In a virtual environment with pip ≥ 21.1, run
```shell
pip install -e .[dev]
```

To run the unit tests, you can either use:
```shell
tox -e py
```
or
```shell
trial tests
```

To run the linters and `mypy` type checker, use `./scripts-dev/lint.sh`.


## Releasing

The exact steps for releasing will vary; but this is an approach taken by the
Synapse developers (assuming a Unix-like shell):

 1. Set a shell variable to the version you are releasing (this just makes
    subsequent steps easier):
    ```shell
    version=X.Y.Z
    ```

 2. Update `setup.cfg` so that the `version` is correct.

 3. Stage the changed files and commit.
    ```shell
    git add -u
    git commit -m v$version -n
    ```

 4. Push your changes.
    ```shell
    git push
    ```

 5. When ready, create a signed tag for the release:
    ```shell
    git tag -s v$version
    ```
    Base the tag message on the changelog.

 6. Push the tag.
    ```shell
    git push origin tag v$version
    ```

 7. Create a source distribution and upload it to PyPI:
    ```shell
    python -m build
    twine upload dist/synapse_domain_rule_checker-$version*
    ```
