const LIBRARY_CONFIG = {
  name: "91 Phutthabucha Rd, Bang Mot, Thung Khru, Bangkok 10140, Thailand",

  lat: 13.6517,
  lng: 100.4899,

  checkInRadiusKm: 0.5,
  checkInRadiusMeters: 500,

  earlyCheckInMinutes: 30,
  
  lateLimitMinutes: 15
};

if (typeof module !== "undefined") {
  module.exports = LIBRARY_CONFIG;
}