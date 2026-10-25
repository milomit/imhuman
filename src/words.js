// 256 short, common words that are hard to mishear, so a code can be read aloud on a call.
// Three words give 2^24 (about 16.7 million) combinations; with five tries per check, guessing is hopeless.
export const WORDS = [
  'acorn', 'actor', 'alarm', 'album', 'alley', 'amber', 'angle', 'ankle', 'apple', 'apron', 'arrow', 'atlas',
  'attic', 'autumn', 'bacon', 'badge', 'bagel', 'baker', 'bamboo', 'banana', 'banjo', 'barn', 'basket', 'beach',
  'beard', 'beaver', 'bell', 'berry', 'bishop', 'blanket', 'blossom', 'boat', 'bonfire', 'border', 'bottle',
  'boulder', 'bowl', 'bramble', 'bread', 'breeze', 'brick', 'bridge', 'brush', 'bubble', 'bucket', 'bugle',
  'butter', 'button', 'cabin', 'cactus', 'camel', 'camera', 'candle', 'canoe', 'canyon', 'carpet', 'carrot', 'castle',
  'cedar', 'cello', 'chalk', 'cherry', 'chess', 'circus', 'clover', 'coconut', 'comet', 'compass', 'copper', 'coral',
  'cotton', 'cowboy', 'crayon', 'cricket', 'crown', 'cupcake', 'daisy', 'dancer', 'desert', 'diamond', 'dolphin', 'donkey',
  'dragon', 'drum', 'eagle', 'easel', 'eclipse', 'elbow', 'ember', 'engine', 'falcon', 'feather', 'fence', 'ferry',
  'fiddle', 'flame', 'flute', 'forest', 'fossil', 'fountain', 'fox', 'galaxy', 'garden', 'garlic', 'geyser', 'giant',
  'ginger', 'glacier', 'globe', 'goat', 'goblet', 'gopher', 'grape', 'gravel', 'guitar', 'hammer', 'harbor', 'harp',
  'hazel', 'helmet', 'hermit', 'honey', 'horizon', 'hornet', 'iceberg', 'igloo', 'island', 'ivory', 'jacket', 'jaguar',
  'jelly', 'jewel', 'jungle', 'kayak', 'kettle', 'kitten', 'koala', 'ladder', 'lagoon', 'lantern', 'lemon', 'lettuce',
  'lizard', 'lobster', 'locket', 'magnet', 'mango', 'maple', 'marble', 'meadow', 'melon', 'meteor',
  'mitten', 'monkey', 'moose', 'mosaic', 'muffin', 'mustard', 'napkin', 'nectar', 'needle', 'noodle', 'nugget', 'oasis',
  'ocean', 'olive', 'onion', 'orange', 'orbit', 'orchid', 'otter', 'owl', 'oyster', 'paddle', 'panda',
  'parrot', 'peach', 'peanut', 'pebble', 'pelican', 'pepper', 'piano', 'pickle', 'pigeon', 'pillow', 'pilot', 'pine',
  'pirate', 'planet', 'pocket', 'pony', 'popcorn', 'potato', 'pretzel', 'pumpkin', 'puppet', 'quartz', 'quilt', 'rabbit',
  'raccoon', 'radar', 'radish', 'rainbow', 'raven', 'ribbon', 'river', 'robot', 'rocket', 'saddle', 'salmon', 'sandal',
  'saturn', 'scarf', 'shadow', 'shovel', 'silver', 'skate', 'sled', 'snail', 'sparrow', 'spider', 'spoon',
  'squash', 'statue', 'sunset', 'swan', 'tablet', 'taco', 'teapot', 'temple', 'tennis', 'thunder', 'tiger',
  'toast', 'tomato', 'topaz', 'tractor', 'trumpet', 'tulip', 'tunnel', 'turtle', 'unicorn', 'valley', 'velvet',
  'violin', 'volcano', 'waffle', 'walnut', 'walrus', 'whistle', 'willow', 'window', 'wizard', 'yogurt', 'zebra', 'zipper',
];

if (WORDS.length !== 256 || new Set(WORDS).size !== 256) {
  throw new Error(`Word list must have 256 unique words, has ${new Set(WORDS).size}`);
}

export function newCode() {
  const bytes = crypto.getRandomValues(new Uint8Array(3));
  return Array.from(bytes, (b) => WORDS[b]).join('-');
}

// Accept "Maple rocket, tiger", "maple-rocket-tiger", etc.
export function normalizeCode(raw) {
  return String(raw ?? '')
    .toLowerCase()
    .split(/[^a-z]+/)
    .filter(Boolean)
    .join('-');
}
