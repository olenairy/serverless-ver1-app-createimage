
import { CustomAuthorizerEvent, CustomAuthorizerResult } from 'aws-lambda'
import 'source-map-support/register'

import { verify } from 'jsonwebtoken'
import { JwtToken } from '../../auth/JwtToken'

const cert = `-----BEGIN CERTIFICATE-----
MIIDBTCCAe2gAwIBAgIJP/R/qSQsvMFGMA0GCSqGSIb3DQEBCwUAMCAxHjAcBgNV
BAMTFW9sZW5haXJ5LnVzLmF1dGgwLmNvbTAeFw0yMTAyMjUxNjQ4MTdaFw0zNDEx
MDQxNjQ4MTdaMCAxHjAcBgNVBAMTFW9sZW5haXJ5LnVzLmF1dGgwLmNvbTCCASIw
DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKxIVXTOTsNhwlCqd5z6H+FMnOCP
b465KAVyIcue7InI92MmoYlJecLCAME21DdQrgzuR1qszy/tEYctPA+GR1c5Z6fa
3cuWCbHtXIPe78L9cXh7M5/zGnRuGLMFjpZ1z1vZnd1dH0QVB5pDqbVQj8BSQc9W
EZxLv1SAzGqiJ0HfOvAUNtraG3c7q0936vM/m9+gMFfc16n5psuyXwpwMcHDG15R
72UC/p0Shs/RWkBPEK3ge9BPUFwwEhXpLm9bND4jOl4ogGBLSRpbAAU4EK1ZhNPG
H+tFZJQQAxR6+SNS47fJyB+bn0EzlX7wGcnn9YOzlUB57QV0c09sE0CMuNkCAwEA
AaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUvVrYn2Snpc1Sf/XX4Hk1
SAkNLoAwDgYDVR0PAQH/BAQDAgKEMA0GCSqGSIb3DQEBCwUAA4IBAQBnRlFREdt0
lTEfSLbAG2TfJ+spOIC2/vYfDPLSJ4SDiu3r2YCIfla2+5D0BRXupHcALgo1hFA7
LHwPhiawbJG9rOF9ROMsXbTCphvcewr5p4TE9Ts8V1szJRi4YZjufFACp1GHEDO0
9H+ybvKgjXcV+ibVzkiUdj7fIz1WpoW8y174JXq7y1/T6WjgOuuY5EDwXZcwi9T0
AWD8OVM7Y9cHIDaAUkMs1LKcysSXHGScJxrrgTgSOVejmBwDXpR1c5fx5TdaXGXs
15ZPDrqsoA7Y0X2vCy6R5z145pgd7P4BaCWdg/BJBz/XjeDBvNLoszhqCuepGXlL
txrE/T8EkpnI
-----END CERTIFICATE-----`

export const handler = async (event: CustomAuthorizerEvent): Promise<CustomAuthorizerResult> => {
  try {
    const jwtToken = verifyToken(event.authorizationToken)
    console.log('User was authorized', jwtToken)

    return {
      principalId: jwtToken.sub,
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Allow',
            Resource: '*'
          }
        ]
      }
    }
  } catch (e) {
    console.log('User authorized', e.message)

    return {
      principalId: 'user',
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Deny',
            Resource: '*'
          }
        ]
      }
    }
  }
}

function verifyToken(authHeader: string): JwtToken {
  if (!authHeader)
    throw new Error('No authentication header')

  if (!authHeader.toLowerCase().startsWith('bearer '))
    throw new Error('Invalid authentication header')

  const split = authHeader.split(' ')
  const token = split[1]

  return verify(token, cert, { algorithms: ['RS256'] }) as JwtToken
}
