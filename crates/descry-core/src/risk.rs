use std::fmt;

use serde::de::{Error as DeserializeError, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RiskScore(pub u8);

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Confidence(pub f32);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RiskScoreOutOfRange;

impl fmt::Display for RiskScoreOutOfRange {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("risk score must be between 0 and 100")
    }
}

impl TryFrom<u8> for RiskScore {
    type Error = RiskScoreOutOfRange;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        if value <= 100 {
            Ok(Self(value))
        } else {
            Err(RiskScoreOutOfRange)
        }
    }
}

impl Serialize for RiskScore {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u8(self.0)
    }
}

impl<'de> Deserialize<'de> for RiskScore {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u8::deserialize(deserializer)?;
        Self::try_from(value).map_err(D::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ConfidenceOutOfRange;

impl fmt::Display for ConfidenceOutOfRange {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("confidence must be between 0.0 and 1.0")
    }
}

impl TryFrom<f32> for Confidence {
    type Error = ConfidenceOutOfRange;

    fn try_from(value: f32) -> Result<Self, Self::Error> {
        if (0.0..=1.0).contains(&value) {
            Ok(Self(value))
        } else {
            Err(ConfidenceOutOfRange)
        }
    }
}

impl Serialize for Confidence {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_f32(self.0)
    }
}

impl<'de> Deserialize<'de> for Confidence {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ConfidenceVisitor;

        impl Visitor<'_> for ConfidenceVisitor {
            type Value = Confidence;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a floating point confidence between 0.0 and 1.0")
            }

            fn visit_f32<E>(self, value: f32) -> Result<Self::Value, E>
            where
                E: DeserializeError,
            {
                Confidence::try_from(value).map_err(E::custom)
            }

            fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
            where
                E: DeserializeError,
            {
                if value.is_finite() && value >= f32::MIN as f64 && value <= f32::MAX as f64 {
                    Confidence::try_from(value as f32).map_err(E::custom)
                } else {
                    Err(E::custom(ConfidenceOutOfRange))
                }
            }
        }

        deserializer.deserialize_f32(ConfidenceVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::{Confidence, RiskScore};

    #[test]
    fn risk_score_accepts_bounds() {
        assert_eq!(RiskScore::try_from(0), Ok(RiskScore(0)));
        assert_eq!(RiskScore::try_from(100), Ok(RiskScore(100)));
    }

    #[test]
    fn risk_score_rejects_values_above_one_hundred() {
        assert!(RiskScore::try_from(101).is_err());
        assert!(serde_json::from_str::<RiskScore>("101").is_err());
    }

    #[test]
    fn confidence_accepts_bounds() {
        assert_eq!(Confidence::try_from(0.0), Ok(Confidence(0.0)));
        assert_eq!(Confidence::try_from(1.0), Ok(Confidence(1.0)));
    }

    #[test]
    fn confidence_rejects_values_outside_range() {
        assert!(Confidence::try_from(-0.1).is_err());
        assert!(Confidence::try_from(1.1).is_err());
        assert!(serde_json::from_str::<Confidence>("1.1").is_err());
    }
}
