export function removeSnapById(snaps, id) {
  if (!Array.isArray(snaps)) return snaps;
  return snaps.filter(s => String(s.id) !== String(id));
}

export default { removeSnapById };
