#[cfg(feature = "simd-yuv")]
pub fn bgra_to_yuv420p(
    bgra: &[u8],
    src_w: usize,
    src_h: usize,
    dst_w: usize,
    dst_h: usize,
) -> Vec<u8> {
    let scaled_bgra;
    let (bgra_buf, w, h) = if src_w == dst_w && src_h == dst_h {
        (bgra, src_w, src_h)
    } else {
        scaled_bgra = {
            let mut buf = vec![0u8; dst_w * dst_h * 4];
            for dy in 0..dst_h {
                let sy = (dy * src_h) / dst_h;
                let src_row = sy * src_w;
                let dst_row = dy * dst_w;
                for dx in 0..dst_w {
                    let sx = (dx * src_w) / dst_w;
                    let src_idx = (src_row + sx) * 4;
                    let dst_idx = (dst_row + dx) * 4;
                    if src_idx + 3 < bgra.len() && dst_idx + 3 < buf.len() {
                        buf[dst_idx..dst_idx + 4].copy_from_slice(&bgra[src_idx..src_idx + 4]);
                    }
                }
            }
            buf
        };
        (&scaled_bgra[..], dst_w, dst_h)
    };

    let mut planar =
        yuv::YuvPlanarImageMut::<u8>::alloc(w as u32, h as u32, yuv::YuvChromaSubsampling::Yuv420);

    let _ = yuv::bgra_to_yuv420(
        &mut planar,
        bgra_buf,
        (w * 4) as u32,
        yuv::YuvRange::Limited,
        yuv::YuvStandardMatrix::Bt601,
        yuv::YuvConversionMode::Balanced,
    )
    .map_err(|e| {
        log::error!("bgra_to_yuv420 failed: {:?}", e);
    });

    let mut out = vec![0u8; (w * h) + (w / 2 * h / 2) * 2];
    let y_size = w * h;
    let uv_size = (w / 2) * (h / 2);

    let copy_plane = |store: &yuv::BufferStoreMut<u8>, dest: &mut [u8]| match store {
        yuv::BufferStoreMut::Borrowed(slice) => {
            dest.copy_from_slice(slice);
        }
        yuv::BufferStoreMut::Owned(vec) => {
            dest.copy_from_slice(vec);
        }
    };

    copy_plane(&planar.y_plane, &mut out[0..y_size]);
    copy_plane(&planar.u_plane, &mut out[y_size..(y_size + uv_size)]);
    copy_plane(&planar.v_plane, &mut out[(y_size + uv_size)..]);

    out
}

/// Convert a decoded YUV420p frame into BGRA (`out_bgra` must be `width*height*4`.
#[cfg(feature = "simd-yuv")]
#[allow(clippy::too_many_arguments)]
pub fn yuv420p_to_bgra(
    y: &[u8],
    u: &[u8],
    v: &[u8],
    width: usize,
    height: usize,
    y_stride: usize,
    u_stride: usize,
    v_stride: usize,
    out_bgra: &mut [u8],
) {
    let planar = yuv::YuvPlanarImage::<u8> {
        y_plane: y,
        y_stride: y_stride as u32,
        u_plane: u,
        u_stride: u_stride as u32,
        v_plane: v,
        v_stride: v_stride as u32,
        width: width as u32,
        height: height as u32,
    };
    if let Err(e) = yuv::yuv420_to_bgra(
        &planar,
        out_bgra,
        (width * 4) as u32,
        yuv::YuvRange::Limited,
        yuv::YuvStandardMatrix::Bt601,
    ) {
        log::error!("yuv420_to_bgra failed: {:?}", e);
    }
}

#[cfg(not(feature = "simd-yuv"))]
#[allow(clippy::too_many_arguments)]
pub fn yuv420p_to_bgra(
    y: &[u8],
    u: &[u8],
    v: &[u8],
    width: usize,
    height: usize,
    y_stride: usize,
    u_stride: usize,
    v_stride: usize,
    out_bgra: &mut [u8],
) {
    for h in 0..height {
        for w in 0..width {
            let y_idx = h * y_stride + w;
            let u_idx = (h / 2) * u_stride + (w / 2);
            let v_idx = (h / 2) * v_stride + (w / 2);
            if y_idx >= y.len() || u_idx >= u.len() || v_idx >= v.len() {
                continue;
            }
            let c = y[y_idx] as i32 - 16;
            let d = u[u_idx] as i32 - 128;
            let e = v[v_idx] as i32 - 128;
            let r = ((298 * c + 409 * e + 128) >> 8).clamp(0, 255) as u8;
            let g = ((298 * c - 100 * d - 208 * e + 128) >> 8).clamp(0, 255) as u8;
            let b = ((298 * c + 516 * d + 128) >> 8).clamp(0, 255) as u8;
            let o = (h * width + w) * 4;
            if o + 3 < out_bgra.len() {
                out_bgra[o] = b;
                out_bgra[o + 1] = g;
                out_bgra[o + 2] = r;
                out_bgra[o + 3] = 255;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_size_matches_yuv420p_formula() {
        let w = 8;
        let h = 8;
        let bgra = vec![0u8; w * h * 4];
        let yuv = bgra_to_yuv420p(&bgra, w, h, w, h);
        let expected = w * h + (w / 2) * (h / 2) * 2;
        assert_eq!(yuv.len(), expected, "YUV420p size should be w*h + uv*2");
    }

    #[test]
    fn downscaled_output_has_correct_size() {
        let src_w = 8;
        let src_h = 8;
        let dst_w = 4;
        let dst_h = 4;
        let bgra = vec![128u8; src_w * src_h * 4];
        let yuv = bgra_to_yuv420p(&bgra, src_w, src_h, dst_w, dst_h);
        let expected = dst_w * dst_h + (dst_w / 2) * (dst_h / 2) * 2;
        assert_eq!(yuv.len(), expected);
    }

    #[test]
    fn pure_black_input_produces_nonempty_output() {
        let w = 4;
        let h = 4;
        let bgra = vec![0u8; w * h * 4];
        let yuv = bgra_to_yuv420p(&bgra, w, h, w, h);
        assert!(!yuv.is_empty());
    }

    fn solid_bgra(w: usize, h: usize, b: u8, g: u8, r: u8) -> Vec<u8> {
        let mut bgra = vec![0u8; w * h * 4];
        for px in bgra.chunks_mut(4) {
            px[0] = b;
            px[1] = g;
            px[2] = r;
            px[3] = 255;
        }
        bgra
    }

    fn decode(yuv: &[u8], w: usize, h: usize) -> Vec<u8> {
        let y_size = w * h;
        let uv_size = (w / 2) * (h / 2);
        let mut out = vec![0u8; w * h * 4];
        yuv420p_to_bgra(
            &yuv[0..y_size],
            &yuv[y_size..y_size + uv_size],
            &yuv[y_size + uv_size..],
            w,
            h,
            w,
            w / 2,
            w / 2,
            &mut out,
        );
        out
    }

    #[test]
    fn bgra_yuv_roundtrip_preserves_gray() {
        let (w, h) = (16, 16);
        let bgra = solid_bgra(w, h, 128, 128, 128);
        let out = decode(&bgra_to_yuv420p(&bgra, w, h, w, h), w, h);
        for (i, (a, b)) in bgra.iter().zip(out.iter()).enumerate() {
            if i % 4 == 3 {
                continue; // alpha
            }
            let diff = (*a as i32 - *b as i32).abs();
            assert!(diff <= 6, "channel {i}: {a} vs {b} (diff {diff})");
        }
    }

    #[test]
    fn bgra_yuv_roundtrip_keeps_channel_order() {
        let (w, h) = (16, 16);
        let red = decode(
            &bgra_to_yuv420p(&solid_bgra(w, h, 0, 0, 255), w, h, w, h),
            w,
            h,
        );
        assert!(
            red[2] > 180 && red[0] < 80,
            "red: b={} r={}",
            red[0],
            red[2]
        );
        let blue = decode(
            &bgra_to_yuv420p(&solid_bgra(w, h, 255, 0, 0), w, h, w, h),
            w,
            h,
        );
        assert!(
            blue[0] > 180 && blue[2] < 80,
            "blue: b={} r={}",
            blue[0],
            blue[2]
        );
    }
}

#[cfg(not(feature = "simd-yuv"))]
pub fn bgra_to_yuv420p(
    bgra: &[u8],
    src_w: usize,
    src_h: usize,
    dst_w: usize,
    dst_h: usize,
) -> Vec<u8> {
    let y_size = dst_w * dst_h;
    let uv_size = (dst_w / 2) * (dst_h / 2);
    let mut yuv = vec![0u8; y_size + uv_size * 2];

    let (y_plane, rest) = yuv.split_at_mut(y_size);
    let (u_plane, v_plane) = rest.split_at_mut(uv_size);

    for dy in 0..dst_h {
        let sy = (dy * src_h) / dst_h;
        let row_start_y = dy * dst_w;
        let row_start_bgra = sy * src_w;
        for dx in 0..dst_w {
            let sx = (dx * src_w) / dst_w;
            let src_idx = (row_start_bgra + sx) * 4;
            if src_idx + 3 < bgra.len() {
                let b = bgra[src_idx] as i32;
                let g = bgra[src_idx + 1] as i32;
                let r = bgra[src_idx + 2] as i32;

                let y = (r * 77 + g * 150 + b * 29) >> 8;
                y_plane[row_start_y + dx] = y.clamp(0, 255) as u8;

                if dy % 2 == 0 && dx % 2 == 0 {
                    let u = ((-r * 43 - g * 85 + b * 128) >> 8) + 128;
                    let v = ((r * 128 - g * 107 - b * 21) >> 8) + 128;
                    let uv_idx = (dy / 2) * (dst_w / 2) + (dx / 2);
                    if uv_idx < u_plane.len() && uv_idx < v_plane.len() {
                        u_plane[uv_idx] = u.clamp(0, 255) as u8;
                        v_plane[uv_idx] = v.clamp(0, 255) as u8;
                    }
                }
            }
        }
    }
    yuv
}
