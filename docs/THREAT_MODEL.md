# Threat Model

## Scope

This project is a portfolio dashboard for managing cybersecurity controls and evidence. It is not a production SOC tool.

## Threats considered

- unauthorized access to the dashboard or underlying data
- stale or incomplete evidence attached to compliance controls
- inaccurate risk scoring due to poor ownership or missing control details
- business misuse of the model because it is not a live operational environment

## Security considerations

- keep secrets and credentials out of the repository
- use environment variables for real deployments
- validate user access if the application is extended into a multi-user environment
- avoid treating the dashboard as a representative production security monitoring system

## Risk treatment

The project demonstrates governance controls, not security operations tooling. The key value is in the thought process: identifying risks, mapping controls, assigning ownership, and demonstrating evidence.
