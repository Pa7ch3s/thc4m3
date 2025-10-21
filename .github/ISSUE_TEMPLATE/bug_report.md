name: Bug report
description: Report a problem
labels: bug
body:
- type: textarea
  attributes:
    label: What happened?
    description: Steps to reproduce
  validations:
    required: true
- type: input
  attributes:
    label: Version/tag
- type: textarea
  attributes:
    label: Logs / screenshots
