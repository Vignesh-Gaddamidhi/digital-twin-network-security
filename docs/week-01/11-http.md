# Day 5: Hypertext Transfer Protocol (HTTP)

## 1. Protocol Architecture
- Stateless request-response client-server architecture.
- Default Port: 80 (TCP).
- Text-delimited frames using CRLF (`\r\n`) header separators.

## 2. Core Methods
- `GET`: Read resource without state-altering side effects.
- `POST`: Create entity or execute backend operation.
- `PUT`: Complete idempotent replacement of target resource.
- `PATCH`: Partial modification of resource.
- `DELETE`: Eradicate target resource.

## 3. Status Code Classifications
- `200 OK`: Request succeeded.
- `301 Moved Permanently`: Resource relocated to new URI.
- `400 Bad Request`: Malformed syntactic query.
- `401 Unauthorized`: Missing or invalid credentials.
- `403 Forbidden`: Authenticated identity lacks permission.
- `404 Not Found`: Target resource does not exist.
- `500 Internal Server Error`: Backend execution crash.