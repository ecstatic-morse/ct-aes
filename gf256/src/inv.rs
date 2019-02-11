use super::Element;

fn find_inverse(a: Element) -> Option<Element> {
    (0..=255)
        .map(Element)
        .find(|&b| a * b == Element(1))
}

pub fn inverse_table() -> Vec<Element> {
    // Element 0 is non-invertible
    let mut ret = vec![Element(0)];

    let inv = (1..=255)
        .map(Element)
        .map(|el| find_inverse(el).expect("Non-invertible element"));

    ret.extend(inv);
    ret
}
