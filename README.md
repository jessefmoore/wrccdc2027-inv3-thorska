# WRCCDC 2027 Inv3 - Thorska

A [Ludus source](https://docs.ludus.cloud/docs/using-ludus/sources) packaging
the `thorska` smart-home showroom inject for WRCCDC 2027, following the
layout used by [badsectorlabs/ludus-source-bsl](https://github.com/badsectorlabs/ludus-source-bsl).

## Quick Start

```bash
ludus source add https://github.com/wccomps/wrccdc2027-inv3-thorska

for role in domain_join shell_history step_ca blackteam_ssh podman home_assistant esphome_devices gitea; do
  ludus ansible role add -d ansible/roles/$role
done

ludus blueprint apply wrccdc2027-inv3-thorska/thorska
ludus range deploy
```

## Blueprints

| Blueprint ID | Name | VMs | Description |
|---|---|---|---|
| [`thorska`](./blueprints/thorska/) | Thorska Smart-Home Showroom | 3 | Standalone AD domain + Gitea CI server + a Home Assistant/ESPHome/step-ca showroom box |

## Layout

```
source.yml                   Source metadata
blueprints/thorska/          blueprint.yml, range-config.yml, requirements.yml, README.md, testing/
ansible/roles/                8 private roles, installed via `ludus ansible role add -d`
```
