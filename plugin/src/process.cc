/* THIS CODE IS GENERATED. DON'T CHANGE MANUALLY! */

#include "process.h"
#include "zeek/Val.h"

#pragma GCC diagnostic ignored "-Wunused-variable"
#pragma GCC diagnostic ignored "-Wunused-function"

using namespace zeek;

namespace {

template <typename T> inline const T *ptr(const T *v) { return v; }

template <typename T>
inline typename std::enable_if<!std::is_pointer<T>::value, const T *>::type
ptr(const T &v) {
  return &v;
}

inline IntrusivePtr<Val> convert(const int *i) {
  return make_intrusive<IntVal>(*i);
}
inline IntrusivePtr<Val> convert(const long int *i) {
  return make_intrusive<IntVal>(*i);
}
inline IntrusivePtr<Val> convert(const unsigned int *i) {
  return make_intrusive<IntVal>(*i);
}
inline IntrusivePtr<Val> convert(const long unsigned int *i) {
  return make_intrusive<IntVal>(*i);
}

#ifdef _OBJECT_IDENTIFIER_H_
IntrusivePtr<Val> convert(const OBJECT_IDENTIFIER_t *oid) {
  std::string res;
  unsigned long arcs[100];
  int arc_slots = sizeof(arcs) / sizeof(arcs[0]);
  int count = OBJECT_IDENTIFIER_get_arcs(oid, arcs, sizeof(arcs[0]), arc_slots);
  if (count < 0 || count > arc_slots)
    return nullptr;
  for (int i = 0; i < count; i++) {
    if (i != 0)
      res += ".";
    res += std::to_string(arcs[i]);
  }
  return make_intrusive<StringVal>(res);
}
#endif

template <typename T> inline IntrusivePtr<Val> convert(const T *s) {
  return make_intrusive<StringVal>(s->size,
                                   reinterpret_cast<const char *>(s->buf));
}

bool is_bit_set(const BIT_STRING_t *s, unsigned int idx) {
  int byte_no = idx / 8;
  if (byte_no >= s->size)
    return false;
  auto byte = s->buf[byte_no];
  return byte & (1 << (idx % 8));
}

/*
 * In the event of an error, the function does not return,
 * but deliberately causes a core dump.
 */
template <typename T>
IntrusivePtr<T> get_field_type(IntrusivePtr<RecordVal> container,
                               const char *fieldname) {
  auto tag = TYPE_RECORD;
  if constexpr (std::is_same_v<T, VectorType>)
    tag = TYPE_VECTOR;
  auto container_type = cast_intrusive<RecordType>(container->GetType());
  if (!container_type->HasField(fieldname)) {
    reporter->InternalError("Unable to process '%s': Missing field '%s'",
                            container_type->GetName().c_str(), fieldname);
  }
  auto field_type = container_type->GetFieldType(fieldname);
  if (field_type->Tag() != tag) {
    reporter->InternalError(
        "Unable to process '%s': Field '%s' is of wrong type",
        container_type->GetName().c_str(), fieldname);
  }
  return cast_intrusive<T>(field_type);
}

template <typename T>
IntrusivePtr<T> get_field_type(IntrusivePtr<VectorVal> container) {
  auto tag = TYPE_RECORD;
  if constexpr (std::is_same_v<T, VectorType>)
    tag = TYPE_VECTOR;
  auto subtype = container->GetType()->Yield();
  if (!subtype || subtype->Tag() != tag) {
    reporter->InternalError("Unable to process '%s': Content is of wrong type",
                            container->GetType()->GetName().c_str());
  }
  return cast_intrusive<T>(subtype);
}
} // namespace

namespace zeek::plugin::pres {

IntrusivePtr<Val> process_CP_type(const CP_type_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<RecordType>("pres::CP_type");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->mode_selector);
      const auto src = _new_src;
      const auto res = process_Mode_selector(src);
      container->AssignField("mode_selector", res);
    }

    if (src->normal_mode_parameters) {
      const auto _new_src = ptr(src->normal_mode_parameters);
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {
        static const auto type =
            get_field_type<RecordType>(container, "normal_mode_parameters");
        const auto container = make_intrusive<RecordVal>(type);

        {
          const auto _new_src = ptr(src->protocol_version);
          const auto src = _new_src;
          const auto res = process_Protocol_version(src);
          container->AssignField("protocol_version", res);
        }

        if (src->calling_presentation_selector) {
          const auto _new_src = ptr(src->calling_presentation_selector);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("calling_presentation_selector", res);
        }

        if (src->called_presentation_selector) {
          const auto _new_src = ptr(src->called_presentation_selector);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("called_presentation_selector", res);
        }

        if (src->presentation_context_definition_list) {
          const auto _new_src = ptr(src->presentation_context_definition_list);
          const auto src = _new_src;
          const auto res = process_Context_list(src);
          container->AssignField("presentation_context_definition_list", res);
        }

        if (src->default_context_name) {
          const auto _new_src = ptr(src->default_context_name);
          const auto src = _new_src;
          const auto res = process_Default_context_name(src);
          container->AssignField("default_context_name", res);
        }

        if (src->presentation_requirements) {
          const auto _new_src = ptr(src->presentation_requirements);
          const auto src = _new_src;
          const auto res = process_Presentation_requirements(src);
          container->AssignField("presentation_requirements", res);
        }

        if (src->user_session_requirements) {
          const auto _new_src = ptr(src->user_session_requirements);
          const auto src = _new_src;
          const auto res = process_User_session_requirements(src);
          container->AssignField("user_session_requirements", res);
        }

        {
          const auto _new_src = ptr(src->protocol_options);
          const auto src = _new_src;
          const auto res = process_Protocol_options(src);
          container->AssignField("protocol_options", res);
        }

        if (src->initiators_nominated_context) {
          const auto _new_src = ptr(src->initiators_nominated_context);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("initiators_nominated_context", res);
        }

        if (src->user_data) {
          const auto _new_src = ptr(src->user_data);
          const auto src = _new_src;
          const auto res = process_User_data(src);
          container->AssignField("user_data", res);
        }

        res = container;
      }

      container->AssignField("normal_mode_parameters", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_CPC_type(const CPC_type_t *src) {
  const auto res = process_User_data(src);
  return res;
}

IntrusivePtr<Val> process_CPA_PPDU(const CPA_PPDU_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<RecordType>("pres::CPA_PPDU");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->mode_selector);
      const auto src = _new_src;
      const auto res = process_Mode_selector(src);
      container->AssignField("mode_selector", res);
    }

    if (src->normal_mode_parameters) {
      const auto _new_src = ptr(src->normal_mode_parameters);
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {
        static const auto type =
            get_field_type<RecordType>(container, "normal_mode_parameters");
        const auto container = make_intrusive<RecordVal>(type);

        {
          const auto _new_src = ptr(src->protocol_version);
          const auto src = _new_src;
          const auto res = process_Protocol_version(src);
          container->AssignField("protocol_version", res);
        }

        if (src->responding_presentation_selector) {
          const auto _new_src = ptr(src->responding_presentation_selector);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("responding_presentation_selector", res);
        }

        if (src->presentation_context_definition_result_list) {
          const auto _new_src =
              ptr(src->presentation_context_definition_result_list);
          const auto src = _new_src;
          const auto res = process_Result_list(src);
          container->AssignField("presentation_context_definition_result_list",
                                 res);
        }

        if (src->presentation_requirements) {
          const auto _new_src = ptr(src->presentation_requirements);
          const auto src = _new_src;
          const auto res = process_Presentation_requirements(src);
          container->AssignField("presentation_requirements", res);
        }

        if (src->user_session_requirements) {
          const auto _new_src = ptr(src->user_session_requirements);
          const auto src = _new_src;
          const auto res = process_User_session_requirements(src);
          container->AssignField("user_session_requirements", res);
        }

        {
          const auto _new_src = ptr(src->protocol_options);
          const auto src = _new_src;
          const auto res = process_Protocol_options(src);
          container->AssignField("protocol_options", res);
        }

        if (src->responders_nominated_context) {
          const auto _new_src = ptr(src->responders_nominated_context);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("responders_nominated_context", res);
        }

        if (src->user_data) {
          const auto _new_src = ptr(src->user_data);
          const auto src = _new_src;
          const auto res = process_User_data(src);
          container->AssignField("user_data", res);
        }

        res = container;
      }

      container->AssignField("normal_mode_parameters", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_CPR_PPDU(const CPR_PPDU_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<RecordType>("pres::CPR_PPDU");
    const auto container = make_intrusive<RecordVal>(type);

    if (src->present == CPR_PPDU_PR_normal_mode_parameters) {
      const auto _new_src = ptr(src->choice.normal_mode_parameters);
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {
        static const auto type =
            get_field_type<RecordType>(container, "normal_mode_parameters");
        const auto container = make_intrusive<RecordVal>(type);

        {
          const auto _new_src = ptr(src->protocol_version);
          const auto src = _new_src;
          const auto res = process_Protocol_version(src);
          container->AssignField("protocol_version", res);
        }

        if (src->responding_presentation_selector) {
          const auto _new_src = ptr(src->responding_presentation_selector);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("responding_presentation_selector", res);
        }

        if (src->presentation_context_definition_result_list) {
          const auto _new_src =
              ptr(src->presentation_context_definition_result_list);
          const auto src = _new_src;
          const auto res = process_Result_list(src);
          container->AssignField("presentation_context_definition_result_list",
                                 res);
        }

        if (src->default_context_result) {
          const auto _new_src = ptr(src->default_context_result);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("default_context_result", res);
        }

        if (src->provider_reason) {
          const auto _new_src = ptr(src->provider_reason);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("provider_reason", res);
        }

        if (src->user_data) {
          const auto _new_src = ptr(src->user_data);
          const auto src = _new_src;
          const auto res = process_User_data(src);
          container->AssignField("user_data", res);
        }

        res = container;
      }

      container->AssignField("normal_mode_parameters", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_Abort_type(const Abort_type_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<RecordType>("pres::Abort_type");
    const auto container = make_intrusive<RecordVal>(type);

    if (src->present == Abort_type_PR_aru_ppdu) {
      const auto _new_src = ptr(src->choice.aru_ppdu);
      const auto src = _new_src;
      const auto res = process_ARU_PPDU(src);
      container->AssignField("aru_ppdu", res);
    }

    if (src->present == Abort_type_PR_arp_ppdu) {
      const auto _new_src = ptr(src->choice.arp_ppdu);
      const auto src = _new_src;
      const auto res = process_ARP_PPDU(src);
      container->AssignField("arp_ppdu", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_ARU_PPDU(const ARU_PPDU_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<RecordType>("pres::ARU_PPDU");
    const auto container = make_intrusive<RecordVal>(type);

    if (src->present == ARU_PPDU_PR_normal_mode_parameters) {
      const auto _new_src = ptr(src->choice.normal_mode_parameters);
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {
        static const auto type =
            get_field_type<RecordType>(container, "normal_mode_parameters");
        const auto container = make_intrusive<RecordVal>(type);

        if (src->presentation_context_identifier_list) {
          const auto _new_src = ptr(src->presentation_context_identifier_list);
          const auto src = _new_src;
          const auto res = process_Presentation_context_identifier_list(src);
          container->AssignField("presentation_context_identifier_list", res);
        }

        if (src->user_data) {
          const auto _new_src = ptr(src->user_data);
          const auto src = _new_src;
          const auto res = process_User_data(src);
          container->AssignField("user_data", res);
        }

        res = container;
      }

      container->AssignField("normal_mode_parameters", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_ARP_PPDU(const ARP_PPDU_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<RecordType>("pres::ARP_PPDU");
    const auto container = make_intrusive<RecordVal>(type);

    if (src->provider_reason) {
      const auto _new_src = ptr(src->provider_reason);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("provider_reason", res);
    }

    if (src->event_identifier) {
      const auto _new_src = ptr(src->event_identifier);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("event_identifier", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_Typed_data_type(const Typed_data_type_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<RecordType>("pres::Typed_data_type");
    const auto container = make_intrusive<RecordVal>(type);

    if (src->present == Typed_data_type_PR_acPPDU) {
      const auto _new_src = ptr(src->choice.acPPDU);
      const auto src = _new_src;
      const auto res = process_AC_PPDU(src);
      container->AssignField("acPPDU", res);
    }

    if (src->present == Typed_data_type_PR_acaPPDU) {
      const auto _new_src = ptr(src->choice.acaPPDU);
      const auto src = _new_src;
      const auto res = process_ACA_PPDU(src);
      container->AssignField("acaPPDU", res);
    }

    if (src->present == Typed_data_type_PR_ttdPPDU) {
      const auto _new_src = ptr(src->choice.ttdPPDU);
      const auto src = _new_src;
      const auto res = process_User_data(src);
      container->AssignField("ttdPPDU", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_AC_PPDU(const AC_PPDU_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<RecordType>("pres::AC_PPDU");
    const auto container = make_intrusive<RecordVal>(type);

    if (src->presentation_context_addition_list) {
      const auto _new_src = ptr(src->presentation_context_addition_list);
      const auto src = _new_src;
      const auto res = process_Context_list(src);
      container->AssignField("presentation_context_addition_list", res);
    }

    if (src->presentation_context_deletion_list) {
      const auto _new_src = ptr(src->presentation_context_deletion_list);
      const auto src = _new_src;
      const auto res = process_Presentation_context_deletion_list(src);
      container->AssignField("presentation_context_deletion_list", res);
    }

    if (src->user_data) {
      const auto _new_src = ptr(src->user_data);
      const auto src = _new_src;
      const auto res = process_User_data(src);
      container->AssignField("user_data", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_ACA_PPDU(const ACA_PPDU_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<RecordType>("pres::ACA_PPDU");
    const auto container = make_intrusive<RecordVal>(type);

    if (src->presentation_context_addition_result_list) {
      const auto _new_src = ptr(src->presentation_context_addition_result_list);
      const auto src = _new_src;
      const auto res = process_Result_list(src);
      container->AssignField("presentation_context_addition_result_list", res);
    }

    if (src->presentation_context_deletion_result_list) {
      const auto _new_src = ptr(src->presentation_context_deletion_result_list);
      const auto src = _new_src;
      const auto res = process_Presentation_context_deletion_result_list(src);
      container->AssignField("presentation_context_deletion_result_list", res);
    }

    if (src->user_data) {
      const auto _new_src = ptr(src->user_data);
      const auto src = _new_src;
      const auto res = process_User_data(src);
      container->AssignField("user_data", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_RS_PPDU(const RS_PPDU_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<RecordType>("pres::RS_PPDU");
    const auto container = make_intrusive<RecordVal>(type);

    if (src->presentation_context_identifier_list) {
      const auto _new_src = ptr(src->presentation_context_identifier_list);
      const auto src = _new_src;
      const auto res = process_Presentation_context_identifier_list(src);
      container->AssignField("presentation_context_identifier_list", res);
    }

    if (src->user_data) {
      const auto _new_src = ptr(src->user_data);
      const auto src = _new_src;
      const auto res = process_User_data(src);
      container->AssignField("user_data", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_RSA_PPDU(const RSA_PPDU_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<RecordType>("pres::RSA_PPDU");
    const auto container = make_intrusive<RecordVal>(type);

    if (src->presentation_context_identifier_list) {
      const auto _new_src = ptr(src->presentation_context_identifier_list);
      const auto src = _new_src;
      const auto res = process_Presentation_context_identifier_list(src);
      container->AssignField("presentation_context_identifier_list", res);
    }

    if (src->user_data) {
      const auto _new_src = ptr(src->user_data);
      const auto src = _new_src;
      const auto res = process_User_data(src);
      container->AssignField("user_data", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_Called_presentation_selector(
    const Called_presentation_selector_t *src) {
  const auto res = convert(src);
  return res;
}

IntrusivePtr<Val> process_Calling_presentation_selector(
    const Calling_presentation_selector_t *src) {
  const auto res = convert(src);
  return res;
}

IntrusivePtr<Val> process_Context_list(const Context_list_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<VectorType>("pres::Context_list");
    const auto container = make_intrusive<VectorVal>(type);
    for (int i = 0; i < src->list.count; i++) {
      const auto _new_src = src->list.array[i];
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {
        static const auto type = get_field_type<RecordType>(container);
        const auto container = make_intrusive<RecordVal>(type);

        {
          const auto _new_src = ptr(src->presentation_context_identifier);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("presentation_context_identifier", res);
        }

        {
          const auto _new_src = ptr(src->abstract_syntax_name);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("abstract_syntax_name", res);
        }

        {
          const auto _new_src = ptr(src->transfer_syntax_name_list);
          const auto src = _new_src;

          IntrusivePtr<Val> res;
          {
            static const auto type = get_field_type<VectorType>(
                container, "transfer_syntax_name_list");
            const auto container = make_intrusive<VectorVal>(type);
            for (int i = 0; i < src->list.count; i++) {
              const auto _new_src = src->list.array[i];
              const auto src = _new_src;
              const auto res = convert(src);
              container->Append(res);
            }
            res = container;
          }

          container->AssignField("transfer_syntax_name_list", res);
        }

        res = container;
      }

      container->Append(res);
    }
    res = container;
  }
  return res;
}

IntrusivePtr<Val>
process_Default_context_name(const Default_context_name_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("pres::Default_context_name");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->abstract_syntax_name);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("abstract_syntax_name", res);
    }

    {
      const auto _new_src = ptr(src->transfer_syntax_name);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("transfer_syntax_name", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val>
process_Default_context_result(const Default_context_result_t *src) {
  const auto res = convert(src);
  return res;
}

IntrusivePtr<Val> process_Mode_selector(const Mode_selector_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<RecordType>("pres::Mode_selector");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->mode_value);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("mode_value", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_Presentation_context_addition_list(
    const Presentation_context_addition_list_t *src) {
  const auto res = process_Context_list(src);
  return res;
}

IntrusivePtr<Val> process_Presentation_context_addition_result_list(
    const Presentation_context_addition_result_list_t *src) {
  const auto res = process_Result_list(src);
  return res;
}

IntrusivePtr<Val> process_Presentation_context_definition_list(
    const Presentation_context_definition_list_t *src) {
  const auto res = process_Context_list(src);
  return res;
}

IntrusivePtr<Val> process_Presentation_context_definition_result_list(
    const Presentation_context_definition_result_list_t *src) {
  const auto res = process_Result_list(src);
  return res;
}

IntrusivePtr<Val> process_Presentation_context_deletion_list(
    const Presentation_context_deletion_list_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<VectorType>("pres::Presentation_context_deletion_list");
    const auto container = make_intrusive<VectorVal>(type);
    for (int i = 0; i < src->list.count; i++) {
      const auto _new_src = src->list.array[i];
      const auto src = _new_src;
      const auto res = convert(src);
      container->Append(res);
    }
    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_Presentation_context_deletion_result_list(
    const Presentation_context_deletion_result_list_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<VectorType>(
        "pres::Presentation_context_deletion_result_list");
    const auto container = make_intrusive<VectorVal>(type);
    for (int i = 0; i < src->list.count; i++) {
      const auto _new_src = src->list.array[i];
      const auto src = _new_src;
      const auto res = convert(src);
      container->Append(res);
    }
    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_Presentation_context_identifier_list(
    const Presentation_context_identifier_list_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<VectorType>("pres::Presentation_context_identifier_list");
    const auto container = make_intrusive<VectorVal>(type);
    for (int i = 0; i < src->list.count; i++) {
      const auto _new_src = src->list.array[i];
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {
        static const auto type = get_field_type<RecordType>(container);
        const auto container = make_intrusive<RecordVal>(type);

        {
          const auto _new_src = ptr(src->presentation_context_identifier);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("presentation_context_identifier", res);
        }

        {
          const auto _new_src = ptr(src->transfer_syntax_name);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("transfer_syntax_name", res);
        }

        res = container;
      }

      container->Append(res);
    }
    res = container;
  }
  return res;
}

IntrusivePtr<Val>
process_Presentation_requirements(const Presentation_requirements_t *src) {
  static const auto type =
      id::find_type<VectorType>("pres::Presentation_requirements");
  static IntrusivePtr<EnumType> enum_type = nullptr;
  if (!enum_type) {
    auto subtype = type->Yield();
    if (!subtype || subtype->Tag() != TYPE_ENUM)
      reporter->InternalError("Unable to process 'Presentation-requirements': "
                              "%s is not a vector of enums",
                              type->GetName().c_str());
    enum_type = cast_intrusive<EnumType>(subtype);
  }
  auto res = make_intrusive<VectorVal>(type);
  if (src ? is_bit_set(src, 0) : false) /* context-management */
    res->Append(enum_type->GetEnumVal(0));
  if (src ? is_bit_set(src, 1) : false) /* restoration */
    res->Append(enum_type->GetEnumVal(1));
  return res;
}

IntrusivePtr<Val> process_Protocol_options(const Protocol_options_t *src) {
  static const auto type = id::find_type<VectorType>("pres::Protocol_options");
  static IntrusivePtr<EnumType> enum_type = nullptr;
  if (!enum_type) {
    auto subtype = type->Yield();
    if (!subtype || subtype->Tag() != TYPE_ENUM)
      reporter->InternalError("Unable to process 'Protocol-options': "
                              "%s is not a vector of enums",
                              type->GetName().c_str());
    enum_type = cast_intrusive<EnumType>(subtype);
  }
  auto res = make_intrusive<VectorVal>(type);
  if (src ? is_bit_set(src, 0) : false) /* nominated-context */
    res->Append(enum_type->GetEnumVal(0));
  if (src ? is_bit_set(src, 1) : false) /* short-encoding */
    res->Append(enum_type->GetEnumVal(1));
  if (src ? is_bit_set(src, 2) : false) /* packed-encoding-rules */
    res->Append(enum_type->GetEnumVal(2));
  return res;
}

IntrusivePtr<Val> process_Protocol_version(const Protocol_version_t *src) {
  static const auto type = id::find_type<VectorType>("pres::Protocol_version");
  static IntrusivePtr<EnumType> enum_type = nullptr;
  if (!enum_type) {
    auto subtype = type->Yield();
    if (!subtype || subtype->Tag() != TYPE_ENUM)
      reporter->InternalError("Unable to process 'Protocol-version': "
                              "%s is not a vector of enums",
                              type->GetName().c_str());
    enum_type = cast_intrusive<EnumType>(subtype);
  }
  auto res = make_intrusive<VectorVal>(type);
  if (src ? is_bit_set(src, 0) : false) /* version-1 */
    res->Append(enum_type->GetEnumVal(0));
  return res;
}

IntrusivePtr<Val> process_Responding_presentation_selector(
    const Responding_presentation_selector_t *src) {
  const auto res = convert(src);
  return res;
}

IntrusivePtr<Val> process_Result_list(const Result_list_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<VectorType>("pres::Result_list");
    const auto container = make_intrusive<VectorVal>(type);
    for (int i = 0; i < src->list.count; i++) {
      const auto _new_src = src->list.array[i];
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {
        static const auto type = get_field_type<RecordType>(container);
        const auto container = make_intrusive<RecordVal>(type);

        {
          const auto _new_src = ptr(src->result);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("result", res);
        }

        if (src->transfer_syntax_name) {
          const auto _new_src = ptr(src->transfer_syntax_name);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("transfer_syntax_name", res);
        }

        if (src->provider_reason) {
          const auto _new_src = ptr(src->provider_reason);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("provider_reason", res);
        }

        res = container;
      }

      container->Append(res);
    }
    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_User_data(const User_data_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<RecordType>("pres::User_data");
    const auto container = make_intrusive<RecordVal>(type);

    if (src->present == User_data_PR_simply_encoded_data) {
      const auto _new_src = ptr(src->choice.simply_encoded_data);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("simply_encoded_data", res);
    }

    if (src->present == User_data_PR_fully_encoded_data) {
      const auto _new_src = ptr(src->choice.fully_encoded_data);
      const auto src = _new_src;
      const auto res = process_Fully_encoded_data(src);
      container->AssignField("fully_encoded_data", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_Fully_encoded_data(const Fully_encoded_data_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<VectorType>("pres::Fully_encoded_data");
    const auto container = make_intrusive<VectorVal>(type);
    for (int i = 0; i < src->list.count; i++) {
      const auto _new_src = src->list.array[i];
      const auto src = _new_src;
      const auto res = process_PDV_list(src);
      container->Append(res);
    }
    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_PDV_list(const PDV_list_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<RecordType>("pres::PDV_list");
    const auto container = make_intrusive<RecordVal>(type);

    if (src->transfer_syntax_name) {
      const auto _new_src = ptr(src->transfer_syntax_name);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("transfer_syntax_name", res);
    }

    {
      const auto _new_src = ptr(src->presentation_context_identifier);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("presentation_context_identifier", res);
    }

    {
      const auto _new_src = ptr(src->presentation_data_values);
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {
        static const auto type =
            get_field_type<RecordType>(container, "presentation_data_values");
        const auto container = make_intrusive<RecordVal>(type);

        if (src->present ==
            PDV_list__presentation_data_values_PR_single_ASN1_type) {
          const auto _new_src = ptr(src->choice.single_ASN1_type);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("single_ASN1_type", res);
        }

        if (src->present ==
            PDV_list__presentation_data_values_PR_octet_aligned) {
          const auto _new_src = ptr(src->choice.octet_aligned);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("octet_aligned", res);
        }

        if (src->present == PDV_list__presentation_data_values_PR_arbitrary) {
          const auto _new_src = ptr(src->choice.arbitrary);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("arbitrary", res);
        }

        res = container;
      }

      container->AssignField("presentation_data_values", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val>
process_User_session_requirements(const User_session_requirements_t *src) {
  static const auto type =
      id::find_type<VectorType>("pres::User_session_requirements");
  static IntrusivePtr<EnumType> enum_type = nullptr;
  if (!enum_type) {
    auto subtype = type->Yield();
    if (!subtype || subtype->Tag() != TYPE_ENUM)
      reporter->InternalError("Unable to process 'User-session-requirements': "
                              "%s is not a vector of enums",
                              type->GetName().c_str());
    enum_type = cast_intrusive<EnumType>(subtype);
  }
  auto res = make_intrusive<VectorVal>(type);
  if (src ? is_bit_set(src, 0) : false) /* half-duplex */
    res->Append(enum_type->GetEnumVal(0));
  if (src ? is_bit_set(src, 1) : false) /* duplex */
    res->Append(enum_type->GetEnumVal(1));
  if (src ? is_bit_set(src, 2) : false) /* expedited-data */
    res->Append(enum_type->GetEnumVal(2));
  if (src ? is_bit_set(src, 3) : false) /* minor-synchronize */
    res->Append(enum_type->GetEnumVal(3));
  if (src ? is_bit_set(src, 4) : false) /* major-synchronize */
    res->Append(enum_type->GetEnumVal(4));
  if (src ? is_bit_set(src, 5) : false) /* resynchronize */
    res->Append(enum_type->GetEnumVal(5));
  if (src ? is_bit_set(src, 6) : false) /* activity-management */
    res->Append(enum_type->GetEnumVal(6));
  if (src ? is_bit_set(src, 7) : false) /* negotiated-release */
    res->Append(enum_type->GetEnumVal(7));
  if (src ? is_bit_set(src, 8) : false) /* capability-data */
    res->Append(enum_type->GetEnumVal(8));
  if (src ? is_bit_set(src, 9) : false) /* exceptions */
    res->Append(enum_type->GetEnumVal(9));
  if (src ? is_bit_set(src, 10) : false) /* typed-data */
    res->Append(enum_type->GetEnumVal(10));
  if (src ? is_bit_set(src, 11) : false) /* symmetric-synchronize */
    res->Append(enum_type->GetEnumVal(11));
  if (src ? is_bit_set(src, 12) : false) /* data-separation */
    res->Append(enum_type->GetEnumVal(12));
  return res;
}

} // namespace zeek::plugin::pres
