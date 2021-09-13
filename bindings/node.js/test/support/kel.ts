let countEvents = (KEL: string) => KEL.match(/\{((?:[^{}]*\{[^{}]*\})*[^{}]*?)\}/g).length;

export { countEvents };
