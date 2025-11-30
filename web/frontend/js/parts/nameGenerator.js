const PHONETIC_WORDS = [
    'Alpha', 'Bravo', 'Charlie', 'Delta', 'Echo', 'Foxtrot', 'Golf', 'Oscar', 'Sierra', 'Whiskey',
]

export function generateServerName(gameName = 'Server') {
  const word = PHONETIC_WORDS[Math.floor(Math.random() * PHONETIC_WORDS.length)]
  const number = Math.floor(Math.random() * 90) + 10

  return `${gameName} ${word}-${number}`
}
